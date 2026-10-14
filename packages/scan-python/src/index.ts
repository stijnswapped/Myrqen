import fs from "node:fs/promises";
import path from "node:path";
import { parsePython } from "./syntax/convert.js";
import type { ClassDef, FunctionDef, Stmt } from "./syntax/ast.js";
import { indexModule, Project, type PyModule } from "./project/modules.js";
import { FrameworkModel, type RouteInfo } from "./project/frameworks.js";
import { routeLabelAt, siblingRoutes } from "./project/methods.js";
import { TypeReader } from "./project/types.js";
import { Engine, type Frame, type SessionWrite, type StoredWrite } from "./analysis/engine.js";
import type { SinkHit } from "./analysis/sinks.js";
import { describeOrigins, hasSourceOrigin, type Origin, type Taint } from "./analysis/values.js";
import { FLOW_RULES, RULE_IDS } from "./rules/catalogue.js";
import { debugMode, hardcodedSecrets, insecureCookies } from "./rules/config.js";
import { missingAuthentication, objectLevelAuthorization } from "./rules/access.js";
import type { PyCandidate, PythonScanOptions, PythonScanResult } from "./types.js";

export type { PyCandidate, PythonScanOptions, PythonScanResult } from "./types.js";
export { RULE_IDS as PYTHON_RULE_IDS } from "./rules/catalogue.js";
export { parsePython } from "./syntax/convert.js";

const DEFAULT_MAX_FILES = 3000;
const DEFAULT_MAX_FILE_BYTES = 512 * 1024;
const TEMPLATE_MAX_BYTES = 256 * 1024;

const IGNORED_DIRECTORIES = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  "venv",
  ".venv",
  "env",
  ".env",
  "virtualenv",
  "__pycache__",
  "site-packages",
  ".tox",
  ".nox",
  ".mypy_cache",
  ".pytest_cache",
  ".ruff_cache",
  ".myrqen",
  ".cache",
  ".eggs",
  "htmlcov",
  "coverage",
  ".turbo",
  ".next"
]);

const PYTHON_TEST_FILE = /(^|\/)(tests?|testing)(\/|$)|(^|\/)test_[^/]*\.py$|_tests?\.py$|(^|\/)conftest\.py$/;
const TEMPLATE_FILE = /\.(html?|jinja2?|j2|xml|txt)$/;

/** What the Python pass cannot see, stated in every report that parsed Python. */
const PYTHON_LIMITS = [
  "Python entry points are recognised for FastAPI and Flask. Django, class-based views (Flask MethodView), plain Starlette, aiohttp, Tornado and other frameworks are parsed, but their handlers are not recognised as entry points, so data-flow checks do not start from them.",
  "Python data flow follows calls into functions and methods defined in this project, across modules, including functions handed to a background task, thread or task queue with their arguments. A value one route stores in the session is followed, by key, to the routes that read it back, and a value a route writes to a stored record's field is followed, by field name, to unescaped markup and template source that read the field back. It does not follow other callbacks, dynamic dispatch, values kept in caches, stored data reaching other sinks, or decorators that rewrite a handler's arguments.",
  "Python dependency manifests (requirements.txt, pyproject.toml, poetry.lock) are not compared against advisories."
];

export async function scanPython(options: PythonScanOptions): Promise<PythonScanResult> {
  const maxFiles = options.maxFiles ?? DEFAULT_MAX_FILES;
  const maxFileBytes = options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
  const disabled = new Set(options.disabledRules ?? []);
  const isNonApplication = (relative: string) => PYTHON_TEST_FILE.test(relative) || Boolean(options.isNonApplicationFile?.(relative));

  const discovered = await discover(options.repoRoot, maxFiles, maxFileBytes);
  const result: PythonScanResult = {
    candidates: [],
    filesParsed: 0,
    filesSkipped: discovered.skipped,
    bytesParsed: 0,
    routes: 0,
    frameworks: [],
    rulesRun: RULE_IDS.filter((id) => !disabled.has(id)),
    notAssessed: [],
    parseFailures: []
  };
  if (discovered.python.length === 0) return { ...result, rulesRun: [] };

  const project = new Project();
  let nonApplication = 0;
  let damaged = 0;
  for (const file of discovered.python) {
    const relative = path.relative(options.repoRoot, file).split(path.sep).join("/");
    if (isNonApplication(relative)) {
      nonApplication += 1;
      continue;
    }
    let text: string;
    try {
      text = await fs.readFile(file, "utf8");
    } catch (error) {
      result.parseFailures.push({ file: relative, reason: error instanceof Error ? error.message : "unreadable" });
      continue;
    }
    try {
      const { module, errors } = parsePython(text);
      if (errors > 0) damaged += 1;
      project.add(indexModule(relative, text, module, errors));
      result.filesParsed += 1;
      result.bytesParsed += Buffer.byteLength(text);
    } catch (error) {
      result.parseFailures.push({ file: relative, reason: error instanceof Error ? error.message : "parse failed" });
    }
  }
  result.filesSkipped += nonApplication;

  const types = new TypeReader(project);
  const frameworks = new FrameworkModel(project, types);
  result.routes = frameworks.routes.length;
  result.frameworks = [...frameworks.frameworks].map((name) => (name === "fastapi" ? "FastAPI" : "Flask")).sort();

  const templates = discovered.templates;
  const engine = new Engine(project, frameworks, types, (name) => {
    const match = [...templates.keys()].find((key) => key.endsWith(`templates/${name}`));
    return match ? templates.get(match) ?? null : null;
  });

  const candidates: PyCandidate[] = [];
  const report = (candidate: PyCandidate) => {
    if (!disabled.has(candidate.ruleId)) candidates.push(candidate);
  };
  const run = (label: string, file: string, work: () => void) => {
    try {
      work();
    } catch (error) {
      result.parseFailures.push({ file, reason: `${label} failed: ${error instanceof Error ? error.message : "unknown error"}` });
    }
  };

  // Data flow from every route, then from every other function, so that a
  // Flask helper reading `request` directly is still followed.
  // Every route is analysed before any finding is reported, because a value one
  // route reads back from the session is attacker data only if another route
  // stored attacker data under that key.
  const frames = new Map<RouteInfo, Frame>();
  for (const route of frameworks.routes) {
    run("python data-flow analysis", route.module.relativePath, () => {
      frames.set(route, engine.analyzeRoute(route, classOf(route.module, route.fn)));
    });
  }
  const settle = (hit: SinkHit): SinkHit | null => {
    const sessionResolved = resolveSessionTaint(hit, engine.sessionWrites);
    const taint = sessionResolved && resolveStoredTaint({ ...hit, taint: sessionResolved }, engine.storedWrites);
    return taint && hasSourceOrigin(taint) ? { ...hit, taint } : null;
  };
  for (const route of frameworks.routes) {
    const frame = frames.get(route);
    if (!frame) continue;
    run("python data-flow analysis", route.module.relativePath, () => {
      for (const raw of frame.hits) {
        const hit = settle(raw);
        if (hit) report(flowCandidate(hit, flowRoute(frameworks.routes, route, hit), route.module));
      }
      objectLevelAuthorization({ project, report, callTarget: (call) => engine.callTargets.get(call) }, route, frame.lookups, siblingRoutes(frameworks.routes, route));
    });
  }
  for (const module of project.modules) {
    for (const { fn, cls } of functionsOf(module.ast.body)) {
      if (frameworks.routeOf(fn)) continue;
      run("python data-flow analysis", module.relativePath, () => {
        const summary = engine.summary(module, fn, cls);
        for (const raw of summary.hits) {
          const hit = settle(raw);
          if (hit) report(flowCandidate(hit, undefined, module));
        }
      });
    }
    run("python configuration rules", module.relativePath, () => {
      const context = { project, frameworks, report };
      hardcodedSecrets(context, module);
      debugMode(context, module);
      insecureCookies(context, module);
    });
  }
  run("python authentication rule", ".", () => missingAuthentication({ project, report }, frameworks.routes));

  result.candidates = dedupe(candidates);

  /* ---- coverage ---- */
  result.notAssessed.push(...PYTHON_LIMITS);
  if (nonApplication > 0) {
    result.notAssessed.push(`${nonApplication} Python test file(s) were not analysed, because insecure code is expected there.`);
  }
  if (damaged > 0) {
    result.notAssessed.push(`${damaged} Python file(s) contained syntax the parser could not read; they were analysed around the unreadable part.`);
  }
  const withoutRoutes = project.modules.filter((module) => !frameworks.routes.some((route) => route.module === module)).length;
  if (result.filesParsed > 0 && frameworks.routes.length === 0) {
    result.notAssessed.push(
      `No FastAPI or Flask route was recognised in ${result.filesParsed} parsed Python file(s). Data-flow checks start from a route, so they did not run — treat a clean Python result for this project as unproven rather than as evidence of safety.`
    );
  } else if (withoutRoutes > 0) {
    result.notAssessed.push(
      `${withoutRoutes} of ${result.filesParsed} Python file(s) declare no route; they were analysed only as code reachable from the ${frameworks.routes.length} recognised route(s) (${result.frameworks.join(", ")}).`
    );
  }
  return result;
}

/* --------------------------------------------------------------- helpers */

/**
 * The operation a flow finding belongs to. A multi-method handler is one route per
 * method; the finding belongs to the method that reaches the sink, and when only
 * submitted data (a form, a body, an upload) reaches it, a GET cannot be the request
 * that carried it.
 */
function flowRoute(routes: readonly RouteInfo[], route: RouteInfo, hit: SinkHit): string {
  const siblings = siblingRoutes(routes, route);
  return routeLabelAt(siblings, hit.module === route.module ? hit.span.line : undefined, onlySubmittedData(hit.taint)) ?? `${route.methods[0]} ${route.path}`;
}

/**
 * Replace each session read in a hit's taint with what was stored under its key.
 *
 * A read of a key no route filled with attacker data is the application's own
 * state and drops out. A key some route filled with attacker data that is not made
 * safe for this sink keeps the hit, labelled with where the data came from. Null
 * when nothing attacker-controlled remains.
 */
function resolveSessionTaint(hit: SinkHit, writes: ReadonlyMap<string, SessionWrite[]>): Taint | null {
  const reads = hit.taint.origins.filter((origin) => origin.kind === "source" && origin.source === "session");
  if (reads.length === 0) return hit.taint;
  const origins: Origin[] = hit.taint.origins.filter((origin) => !(origin.kind === "source" && origin.source === "session"));
  for (const read of reads) {
    if (read.kind !== "source" || !read.key) continue;
    const stored = (writes.get(read.key) ?? []).filter((write) => !write.taint.clean.has(hit.sink));
    if (stored.length === 0) continue;
    const from = describeOrigins({ origins: stored.flatMap((write) => write.taint.origins), clean: new Set() });
    const first = stored[0]!;
    origins.push({ ...read, label: `session value ${read.key}, stored from ${from} at ${first.module.relativePath}:${first.line}` });
  }
  return origins.length > 0 ? { origins, clean: hit.taint.clean } : null;
}

/** The sinks where data read back from a stored record is followed: unescaped markup and template source. */
const STORED_DATA_SINKS: ReadonlySet<string> = new Set(["xss", "template"]);

/**
 * Replace each stored-field read in a hit's taint with what routes wrote to that field.
 *
 * A field no route wrote attacker data to is the application's own data and drops out,
 * and so does every stored read reaching a sink other than markup or template source:
 * stored data reaching SQL or a shell is a different, rarer defect, and reporting every
 * database value as attacker data there would bury the real findings.
 */
function resolveStoredTaint(hit: SinkHit, writes: ReadonlyMap<string, StoredWrite[]>): Taint | null {
  const reads = hit.taint.origins.filter((origin) => origin.kind === "source" && origin.source === "stored");
  if (reads.length === 0) return hit.taint;
  const origins: Origin[] = hit.taint.origins.filter((origin) => !(origin.kind === "source" && origin.source === "stored"));
  if (STORED_DATA_SINKS.has(hit.sink)) {
    for (const read of reads) {
      if (read.kind !== "source" || !read.key) continue;
      const stored = (writes.get(read.key) ?? []).filter((write) => !write.taint.clean.has(hit.sink));
      if (stored.length === 0) continue;
      const from = describeOrigins({ origins: stored.flatMap((write) => write.taint.origins), clean: new Set() });
      const first = stored[0]!;
      origins.push({ ...read, label: `stored field ${read.key}, written from ${from} at ${first.module.relativePath}:${first.line}` });
    }
  }
  return origins.length > 0 ? { origins, clean: hit.taint.clean } : null;
}

function onlySubmittedData(taint: Taint): boolean {
  const sources = taint.origins.filter((origin) => origin.kind === "source");
  return sources.length > 0 && sources.every((origin) => origin.kind === "source" && (origin.source === "form" || origin.source === "body" || origin.source === "file"));
}

function flowCandidate(hit: SinkHit, route: string | undefined, routeModule: PyModule): PyCandidate {
  const rule = FLOW_RULES[hit.sink];
  const origin = describeOrigins(hit.taint);
  const container = enclosingFunction(hit.module, hit.span.line);
  const crossModule = hit.module !== routeModule;
  const snippet = snippetAround(hit.module.text, hit.span.line, hit.span.endLine);
  return {
    ruleId: rule.id,
    category: rule.category,
    title: rule.title(hit.sinkName),
    severity: rule.severity,
    verification: "strong_evidence",
    summary: rule.summary(origin, hit.sinkName),
    impact: rule.impact,
    remediation: rule.remediation,
    verificationPlan: rule.verificationPlan,
    taxonomy: rule.taxonomy,
    location: {
      file: hit.module.relativePath,
      line: hit.span.line,
      endLine: hit.span.endLine,
      ...(container ? { container } : {})
    },
    ...(route ? { route } : {}),
    evidence: [
      {
        kind: "source",
        description: `${hit.sinkName} receives a value built from ${origin}${hit.detail ? ` (${hit.detail})` : ""}.`,
        snippet,
        location: `${hit.module.relativePath}:${hit.span.line}`
      },
      {
        kind: "source",
        description: `Data flow: ${origin} reaches ${hit.sinkName}${crossModule ? ` in ${hit.module.relativePath}, called from ${route ?? "a route"} in ${routeModule.relativePath}` : ""} with no guard or sanitiser for this kind of sink on the way.`
      }
    ],
    reasoning: `Taint from ${origin} reaches ${hit.sinkName} at ${hit.module.relativePath}:${hit.span.line}${
      crossModule ? `, followed across modules from ${routeModule.relativePath}` : ""
    }; no ${hit.sink === "sql" ? "parameter binding" : hit.sink === "path" ? "containment check" : hit.sink === "ssrf" ? "host allow-list" : "sanitiser"} for this sink applies to it.`
  };
}

function snippetAround(text: string, line: number, endLine: number, context = 2): string {
  const lines = text.split("\n");
  const start = Math.max(0, line - 1 - context);
  const end = Math.min(lines.length, Math.min(endLine, line + 8) + context);
  return lines.slice(start, end).join("\n").slice(0, 1200);
}

function functionsOf(body: Stmt[], cls: ClassDef | null = null): Array<{ fn: FunctionDef; cls: ClassDef | null }> {
  const out: Array<{ fn: FunctionDef; cls: ClassDef | null }> = [];
  for (const stmt of body) {
    if (stmt.k === "funcdef") {
      out.push({ fn: stmt, cls });
      out.push(...functionsOf(stmt.body, null));
    } else if (stmt.k === "classdef") {
      out.push(...functionsOf(stmt.body, stmt));
    } else if (stmt.k === "if" || stmt.k === "try") {
      const blocks = stmt.k === "if" ? stmt.branches.map((branch) => branch.body) : [stmt.body, ...stmt.handlers.map((h) => h.body)];
      for (const block of blocks) out.push(...functionsOf(block, cls));
    }
  }
  return out;
}

function classOf(module: PyModule, fn: FunctionDef): ClassDef | null {
  for (const cls of module.classes.values()) if (cls.body.includes(fn)) return cls;
  return null;
}

function enclosingFunction(module: PyModule, line: number): string | undefined {
  let best: FunctionDef | undefined;
  for (const { fn } of functionsOf(module.ast.body)) {
    if (fn.span.line <= line && fn.span.endLine >= line && (!best || fn.span.line >= best.span.line)) best = fn;
  }
  return best?.name;
}

/** Same category at the same place is one issue; keep the one that knows its route. */
function dedupe(candidates: PyCandidate[]): PyCandidate[] {
  const seen = new Map<string, PyCandidate>();
  for (const candidate of candidates) {
    const key = `${candidate.category}::${candidate.location.file}::${candidate.location.line}`;
    const held = seen.get(key);
    if (!held || (!held.route && candidate.route)) seen.set(key, candidate);
  }
  return [...seen.values()];
}

interface Discovered {
  python: string[];
  templates: Map<string, string>;
  skipped: number;
}

async function discover(root: string, maxFiles: number, maxFileBytes: number): Promise<Discovered> {
  const python: string[] = [];
  const templateFiles: string[] = [];
  let skipped = 0;
  const visit = async (directory: string, inTemplates: boolean): Promise<void> => {
    if (python.length >= maxFiles) return;
    let entries;
    try {
      entries = await fs.readdir(directory, { withFileTypes: true, encoding: "utf8" });
    } catch {
      return;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (python.length >= maxFiles) return;
      const full = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (IGNORED_DIRECTORIES.has(entry.name) || entry.name.startsWith(".")) continue;
        await visit(full, inTemplates || entry.name === "templates");
        continue;
      }
      if (!entry.isFile()) continue;
      if (entry.name.endsWith(".py")) {
        try {
          const { size } = await fs.stat(full);
          if (size > maxFileBytes) {
            skipped += 1;
            continue;
          }
        } catch {
          continue;
        }
        python.push(full);
      } else if (inTemplates && TEMPLATE_FILE.test(entry.name)) {
        templateFiles.push(full);
      }
    }
  };
  await visit(root, false);

  const templates = new Map<string, string>();
  for (const file of templateFiles.slice(0, 500)) {
    try {
      const { size } = await fs.stat(file);
      if (size > TEMPLATE_MAX_BYTES) continue;
      templates.set(path.relative(root, file).split(path.sep).join("/"), await fs.readFile(file, "utf8"));
    } catch {
      // unreadable template: the context check simply has nothing to read
    }
  }
  return { python: python.sort(), templates, skipped };
}
