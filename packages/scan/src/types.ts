import type { EvidenceKind, Severity, Verification } from "@myrqen/contracts";

/**
 * A candidate the static engine believes in. It is deliberately *not* a Finding:
 * the CLI owns identity, redaction, dedupe, and severity normalization, and the
 * host agent may still refute a candidate before it becomes a finding.
 */
export interface Candidate {
  ruleId: string;
  category: string;
  title: string;
  severity: Severity;
  /**
   * Static analysis alone can rarely reach `verified`. A rule states the
   * strongest verification its evidence honestly supports, and the engine never
   * upgrades it.
   */
  verification: Verification;
  summary: string;
  impact: string;
  remediation: string;
  verificationPlan: string;
  taxonomy: string[];
  location: SourceLocation;
  evidence: CandidateEvidence[];
  /** Route or entry point the sink is reachable from, when one was resolved. */
  route?: string;
  /** How the engine reached this conclusion, for the report and for debugging. */
  reasoning: string;
}

export interface SourceLocation {
  file: string;
  line: number;
  endLine?: number;
  /** The enclosing function or route handler, when identifiable. */
  container?: string;
}

export interface CandidateEvidence {
  kind: EvidenceKind;
  description: string;
  snippet?: string;
  location?: string;
}

export interface ScanOptions {
  repoRoot: string;
  /** Hard cap so a huge repository cannot stall a scan. */
  maxFiles?: number;
  maxFileBytes?: number;
  /** Rule ids to skip, for example when the host agent has refuted them. */
  disabledRules?: string[];
  now?: () => Date;
}

export interface ScanCoverage {
  filesParsed: number;
  filesSkipped: number;
  bytesParsed: number;
  languages: string[];
  rulesRun: string[];
  /** Areas the engine cannot reason about, stated so the report can be honest. */
  notAssessed: string[];
  durationMs: number;
  parseFailures: Array<{ file: string; reason: string }>;
}

export interface ScanResult {
  candidates: Candidate[];
  coverage: ScanCoverage;
}

export type RuleSeverity = Severity;

export interface RuleDefinition {
  id: string;
  category: string;
  /** Short description used in coverage notes. */
  describes: string;
}
