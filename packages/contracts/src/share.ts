import type { Finding, ScanReport, Severity } from "./domain.js";

export type ShareMode =
  | "private"
  | "workspace"
  | "account_allowlist"
  | "unlisted"
  | "anyone_with_link";

export const SHARE_MODES: readonly ShareMode[] = [
  "private",
  "workspace",
  "account_allowlist",
  "unlisted",
  "anyone_with_link"
];

export type ReportSectionId = "metadata" | "summary" | "findings" | "coverage" | "limitations" | "methodology";

export const REPORT_SECTION_IDS: readonly ReportSectionId[] = [
  "metadata",
  "summary",
  "findings",
  "coverage",
  "limitations",
  "methodology"
];

export interface FieldMasks {
  evidence?: boolean;
  code?: boolean;
  reproduction?: boolean;
  remediation?: boolean;
  metadata?: boolean;
}

/**
 * Typed, testable projection rules. Deliberately not a programmable policy
 * language: see docs/11-roadmap/NON-GOALS.md.
 */
export interface ProjectionPolicy {
  version: 1;
  sections: { mode: "allow_all" | "allow_only"; ids: string[] };
  findings: { mode: "allow_all" | "allow_only"; ids: string[]; maxSeverity?: Severity };
  fields: FieldMasks;
  anonymize?: boolean;
}

export type PrincipalType = "user" | "email" | "workspace" | "anonymous";

export interface SharePrincipalRule {
  id: string;
  principalType: PrincipalType;
  /** user id, normalized email, or workspace id. Unused for anonymous. */
  principalValue?: string;
  policy: ProjectionPolicy;
  label?: string;
}

export interface ShareConfig {
  id: string;
  reportId: string;
  slug: string;
  mode: ShareMode;
  hasPassword: boolean;
  expiresAt?: string;
  revokedAt?: string;
  anonymousAllowed: boolean;
  defaultPolicy: ProjectionPolicy;
  principals: SharePrincipalRule[];
  createdAt: string;
}

export interface ReportProjection {
  id: string;
  schemaVersion: ScanReport["schemaVersion"];
  projectedFor: { principalType: PrincipalType; label?: string };
  generatedAt?: string;
  project?: ScanReport["project"];
  scan?: ScanReport["scan"];
  authorization?: ScanReport["authorization"];
  summary?: ScanReport["summary"];
  findings?: Finding[];
  coverage?: string[];
  coverageAreas?: ScanReport["coverageAreas"];
  limitations?: string[];
  methodologyVersion?: string;
  redactionNotice?: string;
}

export type ShareResolution =
  | { outcome: "denied"; reason: ShareDenialReason }
  | { outcome: "password_required" }
  | { outcome: "allowed"; policy: ProjectionPolicy; principalType: PrincipalType; label?: string };

export type ShareDenialReason =
  | "not_found"
  | "revoked"
  | "expired"
  | "authentication_required"
  | "not_permitted";
