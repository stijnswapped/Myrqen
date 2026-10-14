import { discoverRoutes, routeCount } from "./ast/routes.js";
// Registers every framework entry-point adapter. Imported for the side effect:
// route discovery and the taint model both look the registry up by name, so it
// has to be populated before the first file is parsed.
import "./ast/frameworks/index.js";
import { entryPointsOf, frameworksIn } from "./ast/entrypoints.js";
import path from "node:path";
import { discoverSourceFiles, isNonApplicationFile, parseFile, type ParsedFile } from "./ast/parse.js";
import { buildRouteIndex, routesForFile } from "./ast/route-index.js";
import { buildCallSiteIndex } from "./ast/call-sites.js";
import { buildServerOwnedCalls } from "./ast/return-provenance.js";
import { buildModuleGraph } from "./engine/modules.js";
import { propagateTaint } from "./engine/interproc.js";
import { createReturnSummariser } from "./engine/summaries.js";
import { graphSchemaResolver } from "./engine/validation.js";
import { decoratedParameterSeeds } from "./engine/decorators.js";
import { handlerPositions, type RequestHandler } from "./engine/handlers.js";
import { assessDependencies, DependencyUsage } from "./dependencies.js";
import { scanPython } from "@myrqen/scan-python";
import { recordScopedToCaller } from "./rules/records.js";
import { debugEndpoint } from "./rules/config.js";
import { commandInjection, sqlInjection } from "./rules/injection.js";
import { dynamicPredicateCompilation, unboundedMonetaryArithmetic, unsafeQueryComposition } from "./rules/logic.js";
import { domHtmlInjection, reflectedXss, verboseErrors } from "./rules/output.js";
import {
  clientBundleSecret,
  massAssignment,
  missingCsrfProtection,
  missingHandlerAuthentication,
  privilegedOperationWithoutRoleCheck,
  sensitiveDataInLogs
} from "./rules/access.js";
import {
  credentialLiteral,
  jwtVerificationBypass,
  legacyDigestAlgorithm,
  predictableSecurityValue,
  sessionCookieConfiguration,
  timingUnsafeSecretComparison,
  weakPasswordStorage
} from "./rules/credentials.js";
import {
  interpreterCodeInjection,
  nosqlInjection,
  prototypePollutingMerge,
  templateInjection,
  unsafeDeserializationParsers,
  xmlExternalEntity
} from "./rules/parsing.js";
import {
  archiveEntryEscape,
  credentialRouteRateLimit,
  crossOriginPolicy,
  filesystemPathTraversal,
  outboundRequestForgery,
  redirectDestinationUnvalidated,
  unboundedResultSet,
  unrestrictedFileUpload
} from "./rules/perimeter.js";
import { RULES_0_3 } from "./rules/registry-0.3.js";
import { routeHintFor, type RouteHint, type Rule, type RuleContext } from "./rules/context.js";
import type ts from "typescript";
import type { Candidate, ScanOptions, ScanResult } from "./types.js";

export * from "./types.js";
export { routeFromFilePath } from "./ast/routes.js";
export { fixedIn } from "./dependencies.js";
export { findCredentialsInText, type TextCredentialHit } from "./secrets-in-text.js";

/**
 * Every rule, in the order a reader would want the report to consider them:
 * injection first, then what the application reads and writes, then who is allowed
 * to ask, then how it handles secrets, then resource limits.
 *
 * Fourteen earlier rules were retired when these landed rather than kept alongside
 * them. Two rules covering one defect at one line produce two findings, and the
 * measured effect of retiring them was precision 0.53 to 0.83 with no loss of
 * recall — most of the engine's noise was the narrower rules, not the new ones.
 */
const RULES: readonly Rule[] = Object.freeze([
  // Injection and interpretation
  commandInjection,
  sqlInjection,
  unsafeQueryComposition,
  nosqlInjection,
  interpreterCodeInjection,
  dynamicPredicateCompilation,
  templateInjection,
  xmlExternalEntity,
  unsafeDeserializationParsers,
  prototypePollutingMerge,

  // What the application reads, writes, fetches, and redirects to
  filesystemPathTraversal,
  archiveEntryEscape,
  unrestrictedFileUpload,
  outboundRequestForgery,
  redirectDestinationUnvalidated,
  reflectedXss,
  domHtmlInjection,

  // Who is allowed to ask
  missingHandlerAuthentication,
  privilegedOperationWithoutRoleCheck,
  recordScopedToCaller,
  massAssignment,
  missingCsrfProtection,
  crossOriginPolicy,

  // Secrets, credentials, and comparisons
  credentialLiteral,
  weakPasswordStorage,
  timingUnsafeSecretComparison,
  predictableSecurityValue,
  legacyDigestAlgorithm,
  jwtVerificationBypass,
  sessionCookieConfiguration,
  clientBundleSecret,

  // Disclosure and limits
  debugEndpoint,
  verboseErrors,
  sensitiveDataInLogs,
  unboundedMonetaryArithmetic,
  credentialRouteRateLimit,
  unboundedResultSet,

  // Added in 0.3; see rules/registry-0.3.ts for why they are listed together.
  ...RULES_0_3
]);

export const RULE_IDS: readonly string[] = RULES.map((rule) => rule.id);

const DEFAULT_MAX_FILES = 3000;
const DEFAULT_MAX_FILE_BYTES = 512 * 1024;

/**
 * What this engine cannot see. Stated in every report so a reader is never left
 * to assume that silence means safety.
 */
const STRUCTURAL_LIMITS: readonly string[] = Object.freeze([
  "In JavaScript and TypeScript, data flow is followed across functions and modules when a resolved call hands caller data from a request handler to another function, up to four calls deep, through ESM and CommonJS imports, re-exports, tsconfig paths and class methods, including the fields of an object argument. zod, yup, joi and valibot schemas are read field by field. A function handed caller data from more than two other modules is treated as a shared utility and not followed into. Values that travel through event emitters, queues, stored callbacks, dynamic dispatch or a call the engine cannot resolve are not connected.",
  "JavaScript, TypeScript and Python source is parsed. Other languages, configuration files, and infrastructure definitions are not analysed, and templates are read only where a Python view renders them.",
  "Runtime behaviour, authentication state, and business rules are not exercised by the static pass; dynamic validation is the host agent's part of the assessment.",
  "Dependency findings compare installed versions (from the lockfile, or exact pins in package.json without one) against an offline advisory snapshot. A finding is raised only where application code imports and uses an export the advisory names; a vulnerable package reached only through another package is listed as present but not reached, because this scan does not follow calls inside dependencies.",
  "A route is reported as the file declares it, or as another module in this scan registered the handler under. Where a router is itself mounted under a prefix further up the application, that prefix is not part of the reported path."
]);

export async function scan(options: ScanOptions): Promise<ScanResult> {
  const startedAt = Date.now();
  const maxFiles = options.maxFiles ?? DEFAULT_MAX_FILES;
  const maxFileBytes = options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
  const disabled = new Set(options.disabledRules ?? []);
  const rules = RULES.filter((rule) => !disabled.has(rule.id));

  const discovered = await discoverSourceFiles(options.repoRoot, { maxFiles, maxFileBytes });
  const candidates: Candidate[] = [];
  const parseFailures: Array<{ file: string; reason: string }> = [];
  const languages = new Set<string>();
  const notAssessed = new Set<string>(STRUCTURAL_LIMITS);
  // Which package exports application code uses, for dependency reachability (ADR 019).
  const dependencyUsage = new DependencyUsage();

  let filesParsed = 0;
  let routesSeen = 0;
  let nonApplicationSkipped = 0;
  const frameworksRecognised = new Set<string>();
  let filesWithoutEntryPoint = 0;
  let crossModuleRoutes = 0;

  // A first pass over the files that look like routers, so a handler module can
  // be told the address another module registered it under.
  //
  // Only files that both mention a path literal and import from a relative
  // specifier are parsed here, which is a small fraction of a repository — the
  // pass costs a filtered re-parse rather than a second parse of everything.
  const routerCandidates: ParsedFile[] = [];
  /*
   * The pre-pass's work is kept rather than thrown away.
   *
   * Every candidate used to be parsed here, handed to `buildRouteIndex`, and then
   * dropped — and the main loop below parsed the same files again. That cost a second
   * parse of each one, and it also discarded every memoised analysis hanging off the
   * first `ts.SourceFile`: the entry-point cache, the declaration index and the taint
   * caches are all `WeakMap`s keyed on that object, so a fresh parse starts cold.
   *
   * Peak memory is essentially unchanged, which is what makes this safe:
   * `buildRouteIndex` already requires every candidate to be live at once, so the
   * high-water mark was reached before this map existed. Holding them through the main
   * loop extends their lifetime, not the peak.
   */
  const alreadyParsed = new Map<string, ParsedFile>();
  for (const absolutePath of discovered.files) {
    const relative = path.relative(options.repoRoot, absolutePath).split(path.sep).join("/");
    if (isNonApplicationFile(relative)) continue;
    const parsed = await parseFile(options.repoRoot, absolutePath);
    if ("error" in parsed) continue;
    if (!/["'`]\//.test(parsed.text) || !/from\s+["'`]\./.test(parsed.text)) continue;
    routerCandidates.push(parsed);
    alreadyParsed.set(absolutePath, parsed);
  }
  const routeIndex = buildRouteIndex(routerCandidates);
  routerCandidates.length = 0;

  /*
   * A second whole-project pass, following the shape of the first.
   *
   * `buildRouteIndex` above reads other modules for addresses only. This one reads them
   * for one further fact: which of a file's exported functions were observed being handed
   * caller data from somewhere else. It exists because a layered application puts the
   * caller's value in a plain parameter one module away, and a file with no entry point
   * has no seeds, so every rule judging a sink inside it stays silent.
   *
   * Every parsed file is needed, not just the router candidates, because a service module
   * imports nothing route-shaped and is exactly the target. The parse is reused from the
   * pre-pass where one exists.
   */
  const indexable: ParsedFile[] = [];
  for (const absolutePath of discovered.files) {
    const relative = path.relative(options.repoRoot, absolutePath).split(path.sep).join("/");
    if (isNonApplicationFile(relative)) continue;
    const reused = alreadyParsed.get(absolutePath);
    const parsed = reused ?? (await parseFile(options.repoRoot, absolutePath));
    if ("error" in parsed) continue;
    alreadyParsed.set(absolutePath, parsed);
    indexable.push(parsed);
  }
  const callSites = buildCallSiteIndex(indexable);
  const serverOwnedCalls = buildServerOwnedCalls(indexable);
  // Attached to the file itself, so the taint model can seed from it without every
  // caller of `analyzeFunction` threading an argument through.
  for (const parsed of indexable) {
    const observed = callSites.get(parsed.relativePath);
    if (observed) parsed.observedParameters = observed;
  }
  /*
   * Inter-procedural taint, across modules and through as many calls as the bounds in
   * `engine/interproc.ts` allow. It writes `parameterSeeds` and `propertySeeds` onto each
   * file, which `analyzeFunction` reads, so every rule that consults the taint model sees
   * a service or helper parameter that a handler somewhere handed caller data — without
   * any rule having to know the call graph exists. See ADR 018.
   */
  const moduleGraph = await buildModuleGraph(options.repoRoot, indexable);
  const resolveSchema = graphSchemaResolver(moduleGraph);
  for (const parsed of indexable) parsed.resolveSchema = resolveSchema;
  const summarise = createReturnSummariser(moduleGraph);
  for (const parsed of indexable) parsed.returnSummary = (call, index) => summarise(parsed, call, index);
  const handlers = handlerPositions(moduleGraph, indexable);
  installRequestSeeds(handlers);
  installDecoratedSeeds(indexable);
  for (const parsed of indexable) parsed.requestHandlerOf = (fn) => handlers.get(fn);
  const interprocedural = propagateTaint(moduleGraph, indexable, { handlers });
  /*
   * The name-keyed view rules such as the record-ownership check consult: the one-hop
   * index's observations, plus every parameter the propagation seeded, in this file or
   * across one. The one-hop index wins where both have a word, so its wording is kept.
   */
  const taintedParametersFor = (relativePath: string): Map<string, Map<number, string>> | undefined => {
    const oneHop = callSites.get(relativePath);
    const propagated = interprocedural.byName.get(relativePath);
    if (!propagated) return oneHop;
    const merged = new Map<string, Map<number, string>>();
    for (const [name, byIndex] of propagated) merged.set(name, new Map(byIndex));
    for (const [name, byIndex] of oneHop ?? []) {
      const into = merged.get(name) ?? new Map<number, string>();
      for (const [index, origin] of byIndex) into.set(index, origin);
      merged.set(name, into);
    }
    return merged;
  };
  installSeedRoutes(indexable, interprocedural.seedSites, (file) => ({
    routes: discoverRoutes(file),
    importedRoutes: routesForFile(routeIndex, file)
  }));
  indexable.length = 0;

  for (const absolutePath of discovered.files) {
    const reused = alreadyParsed.get(absolutePath);
    const parsed = reused ?? (await parseFile(options.repoRoot, absolutePath));
    if ("error" in parsed) {
      parseFailures.push({ file: absolutePath, reason: parsed.error });
      continue;
    }

    // Test and fixture code is not the application's attack surface. Skipping it
    // is the difference between a useful report and a wall of noise about
    // deliberately insecure test doubles.
    if (isNonApplicationFile(parsed.relativePath)) {
      nonApplicationSkipped += 1;
      continue;
    }

    filesParsed += 1;
    languages.add(parsed.language);

    const routes = discoverRoutes(parsed);
    dependencyUsage.record(parsed, routes);
    routesSeen += routeCount(routes);
    for (const framework of frameworksIn(parsed)) frameworksRecognised.add(framework);
    if (entryPointsOf(parsed).length === 0 && routes.length === 0) filesWithoutEntryPoint += 1;

    const importedRoutes = routesForFile(routeIndex, parsed);
    if (routes.length === 0 && importedRoutes.size > 0) crossModuleRoutes += importedRoutes.size;

    const context: RuleContext = {
      file: parsed,
      routes,
      importedRoutes,
      ...(taintedParametersFor(parsed.relativePath) ? { taintedParameters: taintedParametersFor(parsed.relativePath)! } : {}),
      ...(serverOwnedCalls.get(parsed.relativePath)
        ? { serverOwnedCalls: serverOwnedCalls.get(parsed.relativePath)! }
        : {}),
      report: (candidate) => candidates.push(candidate)
    };

    for (const rule of rules) {
      try {
        rule.run(context);
      } catch (error) {
        // A rule that throws must not lose the rest of the scan, but the gap has
        // to be visible rather than swallowed.
        parseFailures.push({
          file: parsed.relativePath,
          reason: `rule ${rule.id} failed: ${error instanceof Error ? error.message : "unknown error"}`
        });
      }
    }
  }

  /*
   * Python, dispatched by language to its own engine (ADR 020). It discovers and
   * parses `.py` files itself and returns candidates in this engine's shape, so
   * everything downstream — dedupe, intake, report — treats them identically. The
   * seam is this one call plus the coverage merge below.
   */
  const python = await scanPython({
    repoRoot: options.repoRoot,
    maxFiles,
    maxFileBytes,
    disabledRules: [...disabled],
    isNonApplicationFile
  });
  candidates.push(...python.candidates);

  if (!disabled.has("dependency-advisory")) {
    const dependencies = await assessDependencies(options.repoRoot, dependencyUsage);
    candidates.push(...dependencies.candidates);
    for (const note of dependencies.notes) notAssessed.add(note);
  }

  if (nonApplicationSkipped > 0) {
    notAssessed.add(
      `${nonApplicationSkipped} test, fixture, or example file(s) were not analysed, because insecure code is expected there.`
    );
  }
  if (discovered.skipped.length > 0) {
    notAssessed.add(
      `${discovered.skipped.length} file(s) were skipped for being symlinks or larger than ${Math.round(maxFileBytes / 1024)} KB.`
    );
  }
  if (discovered.files.length >= maxFiles) {
    notAssessed.add(`The file limit of ${maxFiles} was reached, so part of the repository was not analysed.`);
  }
  if (crossModuleRoutes > 0) {
    notAssessed.add(
      `${crossModuleRoutes} handler(s) were attributed to a route declared in a different module. The route is reported as that router spells it, without any prefix the router is mounted under.`
    );
  }
  if (routesSeen === 0 && filesParsed > 0) {
    notAssessed.add(
      "No HTTP routes were recognised, so route-scoped checks such as authorization coverage had nothing to attach to."
    );
  }

  // The most dangerous thing this engine can do is find nothing in an
  // application it did not understand, and report that as if it had looked.
  //
  // Every data-flow rule starts from an entry point: no entry point means no
  // binding is caller-controlled, which means no rule can fire, which means a
  // file full of defects comes back clean. Measured on a held-out corpus of
  // architectures with no adapter, ten of eleven cases produced no candidate at
  // all for exactly this reason. A reader cannot be expected to infer that from
  // silence, so it is said here in the coverage the report prints.
  if (filesWithoutEntryPoint > 0 && filesParsed > 0) {
    const share = filesWithoutEntryPoint / filesParsed;
    notAssessed.add(
      `No entry point was recognised in ${filesWithoutEntryPoint} of ${filesParsed} parsed file(s)${
        frameworksRecognised.size > 0 ? ` (recognised elsewhere: ${[...frameworksRecognised].sort().join(", ")})` : ""
      }. Data-flow checks need an entry point to know which values a caller controls, so in those files they did not run${
        share > 0.6 ? " — treat a clean result for this project as unproven rather than as evidence of safety" : ""
      }.`
    );
  }

  if (python.filesParsed > 0) languages.add("Python");
  for (const note of python.notAssessed) notAssessed.add(note);

  return {
    candidates: dedupe(candidates),
    coverage: {
      filesParsed: filesParsed + python.filesParsed,
      filesSkipped: discovered.skipped.length + nonApplicationSkipped + python.filesSkipped,
      bytesParsed: discovered.bytes + python.bytesParsed,
      languages: [...languages].sort(),
      rulesRun: [...rules.map((rule) => rule.id), ...python.rulesRun],
      notAssessed: [...notAssessed],
      durationMs: Date.now() - startedAt,
      parseFailures: [...parseFailures, ...python.parseFailures]
    }
  };
}

/**
 * Seed each registered handler's request parameter by position, on the file it lives in.
 *
 * A parameter the name heuristic already recognises keeps its existing origin; this only
 * adds what the heuristic cannot see — a renamed parameter, or a handler declared in one
 * module and registered in another.
 */
/**
 * Parameters a framework's request decorator binds — `@Args('id')`, `@MessageBody()`,
 * `@Path()` — in any method, not only a controller method with a verb decorator.
 * `engine/decorators.ts`. A seed the handler pass already placed is kept.
 */
function installDecoratedSeeds(files: readonly ParsedFile[]): void {
  for (const file of files) {
    const decorated = decoratedParameterSeeds(file);
    if (decorated.size === 0) continue;
    const seeds = (file.requestSeeds ??= new Map());
    for (const [fn, byIndex] of decorated) {
      const into = seeds.get(fn) ?? new Map<number, string>();
      for (const [index, origin] of byIndex) if (!into.has(index)) into.set(index, origin);
      seeds.set(fn, into);
    }
  }
}

function installRequestSeeds(handlers: ReadonlyMap<ts.Node, RequestHandler>): void {
  for (const handler of handlers.values()) {
    const where = handler.path ? `${handler.method === "ANY" ? "" : `${handler.method} `}${handler.path}` : handler.framework;
    const seeds = (handler.file.requestSeeds ??= new Map());
    const byIndex = new Map<number, string>();
    for (const index of handler.requestParameters) {
      const parameter = handler.fn.parameters[index];
      if (!parameter) continue;
      const name = parameter.name.getText(handler.file.source);
      byIndex.set(index, `${name} (request to ${where})`);
    }
    if (byIndex.size > 0) seeds.set(handler.fn, byIndex);
  }
}

/**
 * Give every seeded function the route its seeding call sites answer on.
 *
 * Lazy and memoised: a route is only worked out for a function some rule asks about. A
 * caller that is itself a seeded helper borrows its own callers' route, to the same depth
 * the propagation went; a cycle or a disagreement yields no route, and attribution falls
 * back to what it did before.
 */
function installSeedRoutes(
  files: readonly ParsedFile[],
  seedSites: ReadonlyMap<ts.Node, ReadonlyArray<{ file: ParsedFile; call: ts.Node }>>,
  routeContext: (file: ParsedFile) => { routes: RouteHint[]; importedRoutes: Map<string, RouteHint> }
): void {
  const contexts = new Map<ParsedFile, RuleContext>();
  const contextOf = (file: ParsedFile): RuleContext => {
    let context = contexts.get(file);
    if (!context) {
      context = { file, ...routeContext(file), report: () => undefined };
      contexts.set(file, context);
    }
    return context;
  };
  const memo = new Map<ts.Node, RouteHint | null>();
  const inProgress = new Set<ts.Node>();
  const routeOf = (fn: ts.Node): RouteHint | undefined => {
    if (memo.has(fn)) return memo.get(fn) ?? undefined;
    const sites = seedSites.get(fn);
    if (!sites || sites.length === 0 || inProgress.has(fn)) return undefined;
    inProgress.add(fn);
    let agreed: RouteHint | null = null;
    let conflict = false;
    for (const site of sites) {
      const hint = routeHintFor(contextOf(site.file), site.call);
      if (!hint) continue;
      if (agreed && (agreed.method !== hint.method || agreed.path !== hint.path)) {
        conflict = true;
        break;
      }
      agreed = agreed ?? hint;
    }
    inProgress.delete(fn);
    const result = conflict ? null : agreed;
    memo.set(fn, result);
    return result ?? undefined;
  };
  for (const file of files) file.seedRouteOf = routeOf;
}

/**
 * Two candidates are the same issue when they say the same *kind* of thing about the
 * same place. Deduplicating on structure rather than on prose means rewording cannot
 * create a second finding, which is a property the CLI's own dedupe relies on.
 *
 * The key is the category, not the rule. Two rules reaching one sink is how this engine
 * is meant to work — `code-injection` follows the caller's value to a `new Function()`,
 * and `dynamic-predicate-compilation` says the helper compiles its own parameter
 * regardless of who calls it — and once the cross-file index made the first one reachable,
 * both fired on the same line of `vuln-shop`. Both statements are true. As a *report* it
 * is one defect, one line and one edit, and printing two titles with two remediations
 * spends the reader's attention on reconciling them.
 *
 * Sorting happens after this, so which survives is decided here by arrival order. That is
 * why the loop keeps the first and the callers push the more specific rules first; it is
 * also why this cannot be a set — the surviving candidate carries the evidence.
 */
function dedupe(candidates: Candidate[]): Candidate[] {
  const seen = new Map<string, Candidate>();
  for (const candidate of candidates) {
    const key = `${candidate.category}::${candidate.location.file}::${candidate.location.line}`;
    const held = seen.get(key);
    // Prefer the statement with more to show: a candidate that traced a flow says more
    // about the same line than one that recognised a shape.
    if (!held || (candidate.evidence?.length ?? 0) > (held.evidence?.length ?? 0)) seen.set(key, candidate);
  }
  return [...seen.values()].sort((a, b) => {
    const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const bySeverity = rank[a.severity] - rank[b.severity];
    if (bySeverity !== 0) return bySeverity;
    return a.location.file.localeCompare(b.location.file) || a.location.line - b.location.line;
  });
}

/** Coverage sentences suitable for the report's "assessed" list. */
export function coverageStatements(result: ScanResult): string[] {
  const statements = [
    `Static analysis parsed ${result.coverage.filesParsed} application source file(s) (${result.coverage.languages.join(", ") || "no recognised language"}) and evaluated ${result.coverage.rulesRun.length} rules against the syntax tree.`
  ];
  if (result.coverage.parseFailures.length > 0) {
    statements.push(`${result.coverage.parseFailures.length} file(s) could not be analysed and are listed as limitations.`);
  }
  return statements;
}
