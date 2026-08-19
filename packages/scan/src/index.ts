import { discoverRoutes, routeCount } from "./ast/routes.js";
import { discoverSourceFiles, isNonApplicationFile, parseFile } from "./ast/parse.js";
import { analyzeDependencies } from "./dependencies.js";
import { recordScopedToCaller } from "./rules/records.js";
import { debugEndpoint } from "./rules/config.js";
import { commandInjection, sqlInjection } from "./rules/injection.js";
import { dynamicPredicateCompilation, unboundedMonetaryArithmetic, unsafeQueryComposition } from "./rules/logic.js";
import { reflectedXss, verboseErrors } from "./rules/output.js";
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
import type { Rule, RuleContext } from "./rules/context.js";
import type { Candidate, ScanOptions, ScanResult } from "./types.js";

export * from "./types.js";
export { routeFromFilePath } from "./ast/routes.js";

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
  unboundedResultSet
]);

export const RULE_IDS: readonly string[] = RULES.map((rule) => rule.id);

const DEFAULT_MAX_FILES = 3000;
const DEFAULT_MAX_FILE_BYTES = 512 * 1024;

/**
 * What this engine cannot see. Stated in every report so a reader is never left
 * to assume that silence means safety.
 */
const STRUCTURAL_LIMITS: readonly string[] = Object.freeze([
  "Data flow is followed within a single function. A value that becomes attacker-controlled in one module and is used in another is not connected.",
  "Only JavaScript and TypeScript source is parsed. Other languages, templates, configuration files, and infrastructure definitions are not analysed.",
  "Runtime behaviour, authentication state, and business rules are not exercised by the static pass; dynamic validation is the host agent's part of the assessment.",
  "Dependency findings compare declared versions against a small offline advisory table, without resolving the lockfile or establishing reachability.",
  "A route is reported as the file declares it. Where a router module is mounted under a prefix elsewhere in the application, the prefix is not part of the reported path."
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

  let filesParsed = 0;
  let routesSeen = 0;
  let nonApplicationSkipped = 0;

  for (const absolutePath of discovered.files) {
    const parsed = await parseFile(options.repoRoot, absolutePath);
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
    routesSeen += routeCount(routes);

    const context: RuleContext = {
      file: parsed,
      routes,
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

  if (!disabled.has("dependency-advisory")) {
    candidates.push(...(await analyzeDependencies(options.repoRoot)));
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
  if (routesSeen === 0 && filesParsed > 0) {
    notAssessed.add(
      "No HTTP routes were recognised, so route-scoped checks such as authorization coverage had nothing to attach to."
    );
  }

  return {
    candidates: dedupe(candidates),
    coverage: {
      filesParsed,
      filesSkipped: discovered.skipped.length + nonApplicationSkipped,
      bytesParsed: discovered.bytes,
      languages: [...languages].sort(),
      rulesRun: rules.map((rule) => rule.id),
      notAssessed: [...notAssessed],
      durationMs: Date.now() - startedAt,
      parseFailures
    }
  };
}

/**
 * Two candidates are the same issue when the same rule fires at the same place.
 * Deduplicating on structure rather than on prose means rewording cannot create
 * a second finding, which is a property the CLI's own dedupe relies on.
 */
function dedupe(candidates: Candidate[]): Candidate[] {
  const seen = new Map<string, Candidate>();
  for (const candidate of candidates) {
    const key = `${candidate.ruleId}::${candidate.location.file}::${candidate.location.line}`;
    if (!seen.has(key)) seen.set(key, candidate);
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
