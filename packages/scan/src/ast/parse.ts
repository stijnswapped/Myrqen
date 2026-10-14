import fs from "node:fs/promises";
import path from "node:path";
import ts from "typescript";

export interface ParsedFile {
  /**
   * Which of this file's exported functions were observed being handed caller data by a
   * call in another file: `exported name → parameter index → why`.
   *
   * Set by `scan` after `buildCallSiteIndex` runs, before any rule sees the file. It
   * lives here rather than on `RuleContext` so that `analyzeFunction` can seed a taint
   * scope from it without every caller of it having to thread an argument through — nine
   * of the ten rule files reach the taint model, and the alternative was teaching each
   * one separately about a fact that belongs to the file.
   *
   * Absent when nothing in the project calls into this file.
   */
  observedParameters?: Map<string, Map<number, string>>;
  /**
   * Parameters of functions in this file that a resolved call site, anywhere in the
   * project, was observed handing caller data: `function node → parameter index → why`.
   *
   * Set by `propagateTaint` in `engine/interproc.ts`. Keyed by the function node rather
   * than by name, so two methods called `find` in two classes are never confused. The
   * name-keyed `observedParameters` above is the earlier, one-hop form and is kept.
   */
  parameterSeeds?: Map<import("typescript").Node, Map<number, string>>;
  /**
   * The request parameter of each handler a router or server in this project registered,
   * by position: `function node → parameter index → origin`. Set by `scan` from
   * `engine/handlers.ts`, so a handler whose request parameter is called `rq`, or that is
   * written in a different module from its route, is still read as receiving caller data.
   */
  requestSeeds?: Map<import("typescript").Node, Map<number, string>>;
  /**
   * The same, for an object literal argument: only the properties that held caller data.
   * `load({ id: req.params.id, user: req.user })` seeds `id` and leaves `user` alone.
   */
  propertySeeds?: Map<import("typescript").Node, Map<number, Map<string, string>>>;
  /**
   * What a project function does with an argument, when this call resolves to one:
   * whether any of its returns carries that argument's taint, and whether it hands the
   * argument back by steps the engine reads. `null` when the call does not resolve to a
   * function this scan can read. Installed by `scan` from `engine/summaries.ts`.
   */
  returnSummary?: (call: import("typescript").CallExpression, index: number) => { tainted: boolean; observed: boolean } | null;
  /**
   * The route a function inherits from the call sites that handed it caller data, when
   * they all agree on one. A finding inside a helper or a service belongs to the endpoint
   * that reached it, not to whichever route happens to be declared nearest to the helper.
   * Installed by `scan`; `undefined` when the function was not seeded or its callers
   * disagree.
   */
  seedRouteOf?: (fn: import("typescript").Node) => { method: string; path: string; line: number; node?: import("typescript").Node } | undefined;
  /**
   * Resolves the name of a schema (`JobBody` in `JobBody.parse(req.body)`) to the expression
   * that builds it, across modules. Installed by `scan` from the module graph; without it a
   * schema is read only when declared in the same file. `engine/validation.ts`.
   */
  resolveSchema?: (identifier: import("typescript").Identifier) => import("typescript").Expression | null;
  /**
   * The registration a function is the handler of — its route and the middleware in front
   * of it, wherever the registration is written. Installed by `scan` from
   * `engine/handlers.ts`; `undefined` for a function no router or server registered.
   */
  requestHandlerOf?: (fn: import("typescript").Node) => import("../engine/handlers.js").RequestHandler | undefined;
  /** Repository-relative, POSIX separators, so findings are portable. */
  relativePath: string;
  absolutePath: string;
  text: string;
  source: ts.SourceFile;
  language: "TypeScript" | "JavaScript";
}

const SCRIPT_KINDS: Record<string, ts.ScriptKind> = {
  ".ts": ts.ScriptKind.TS,
  ".tsx": ts.ScriptKind.TSX,
  ".mts": ts.ScriptKind.TS,
  ".cts": ts.ScriptKind.TS,
  ".js": ts.ScriptKind.JS,
  ".jsx": ts.ScriptKind.JSX,
  ".mjs": ts.ScriptKind.JS,
  ".cjs": ts.ScriptKind.JS
};

export const PARSEABLE_EXTENSIONS = Object.keys(SCRIPT_KINDS);

const IGNORED_DIRECTORIES = new Set([
  "node_modules",
  ".git",
  ".next",
  "dist",
  "dist-tsc",
  "build",
  "out",
  "coverage",
  "vendor",
  "target",
  ".venv",
  "venv",
  "__pycache__",
  ".turbo",
  ".pnpm-store",
  ".myrqen",
  ".cache",
  ".audit",
  ".data"
]);

/**
 * Files whose vulnerabilities are not the application's. Reported separately as
 * a coverage note rather than silently dropped, because "we skipped your tests"
 * is information the reader needs.
 */
const NON_APPLICATION = /(^|\/)(tests?|__tests__|__mocks__|e2e|spec|fixtures?|examples?|benchmark)(\/|$)|\.(test|spec)\.[cm]?[jt]sx?$/;

export interface DiscoveredFiles {
  files: string[];
  skipped: string[];
  bytes: number;
}

export async function discoverSourceFiles(
  repoRoot: string,
  options: { maxFiles: number; maxFileBytes: number }
): Promise<DiscoveredFiles> {
  const files: string[] = [];
  const skipped: string[] = [];
  let bytes = 0;

  async function visit(directory: string): Promise<void> {
    if (files.length >= options.maxFiles) return;
    let entries;
    try {
      entries = await fs.readdir(directory, { withFileTypes: true, encoding: "utf8" });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (files.length >= options.maxFiles) return;
      const full = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) {
        // A symlink can point outside the repository or into a cycle. Neither is
        // worth following for an analysis scoped to the project's own source.
        skipped.push(full);
        continue;
      }
      if (entry.isDirectory()) {
        if (IGNORED_DIRECTORIES.has(entry.name) || (entry.name.startsWith(".") && entry.name !== ".github")) continue;
        await visit(full);
        continue;
      }
      if (!entry.isFile()) continue;
      if (!PARSEABLE_EXTENSIONS.includes(path.extname(entry.name))) continue;
      let size = 0;
      try {
        size = (await fs.stat(full)).size;
      } catch {
        continue;
      }
      if (size > options.maxFileBytes) {
        skipped.push(full);
        continue;
      }
      bytes += size;
      files.push(full);
    }
  }

  await visit(repoRoot);
  return { files: files.sort(), skipped, bytes };
}

export function isNonApplicationFile(relativePath: string): boolean {
  return NON_APPLICATION.test(relativePath);
}

export async function parseFile(repoRoot: string, absolutePath: string): Promise<ParsedFile | { error: string }> {
  let text: string;
  try {
    text = await fs.readFile(absolutePath, "utf8");
  } catch (error) {
    return { error: error instanceof Error ? error.message : "unreadable" };
  }

  const extension = path.extname(absolutePath);
  const scriptKind = SCRIPT_KINDS[extension] ?? ts.ScriptKind.TS;
  const relativePath = path.relative(repoRoot, absolutePath).split(path.sep).join("/");

  try {
    const source = ts.createSourceFile(relativePath, text, ts.ScriptTarget.Latest, true, scriptKind);
    return {
      relativePath,
      absolutePath,
      text,
      source,
      language: scriptKind === ts.ScriptKind.JS || scriptKind === ts.ScriptKind.JSX ? "JavaScript" : "TypeScript"
    };
  } catch (error) {
    return { error: error instanceof Error ? error.message : "parse failed" };
  }
}

export function lineOf(file: ParsedFile, node: ts.Node): number {
  return file.source.getLineAndCharacterOfPosition(node.getStart(file.source)).line + 1;
}

export function endLineOf(file: ParsedFile, node: ts.Node): number {
  return file.source.getLineAndCharacterOfPosition(node.getEnd()).line + 1;
}

/**
 * A few lines around the node. Comments are included because a reviewer reading
 * evidence needs the context, but rules never *match* on comments: the parser
 * gives them no AST presence, which is what makes this engine immune to the
 * "scary string in a comment" false positive.
 */
export function snippetAround(file: ParsedFile, node: ts.Node, context = 2): string {
  const lines = file.text.split("\n");
  const start = Math.max(0, lineOf(file, node) - 1 - context);
  const end = Math.min(lines.length, endLineOf(file, node) + context);
  return lines.slice(start, end).join("\n").slice(0, 1200);
}
