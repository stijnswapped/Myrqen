import type { EvidenceKind, Severity, Verification } from "@myrqen/contracts";

/**
 * A candidate finding, in exactly the shape `@myrqen/scan` emits for JavaScript.
 *
 * Declared here rather than imported so the dependency runs one way only —
 * `@myrqen/scan` depends on this package, never the reverse — while TypeScript's
 * structural typing guarantees the two stay interchangeable: a field added on
 * one side and not the other is a compile error at the integration point.
 */
export interface PyCandidate {
  ruleId: string;
  category: string;
  title: string;
  severity: Severity;
  verification: Verification;
  summary: string;
  impact: string;
  remediation: string;
  verificationPlan: string;
  taxonomy: string[];
  location: { file: string; line: number; endLine?: number; container?: string };
  evidence: Array<{ kind: EvidenceKind; description: string; snippet?: string; location?: string }>;
  route?: string;
  reasoning: string;
}

export interface PythonScanOptions {
  repoRoot: string;
  maxFiles?: number;
  maxFileBytes?: number;
  disabledRules?: string[];
  /** The host scanner's notion of test and fixture paths, so both languages skip the same files. */
  isNonApplicationFile?: (relativePath: string) => boolean;
}

export interface PythonScanResult {
  candidates: PyCandidate[];
  filesParsed: number;
  filesSkipped: number;
  bytesParsed: number;
  routes: number;
  frameworks: string[];
  rulesRun: string[];
  notAssessed: string[];
  parseFailures: Array<{ file: string; reason: string }>;
}
