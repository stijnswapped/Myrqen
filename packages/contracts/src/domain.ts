/** Core domain contracts shared by CLI, web, worker, and reports. */

export type EffortRequested = "low" | "high" | "xhigh" | "ultra" | "auto";
export type EffortResolved = Exclude<EffortRequested, "auto">;
export const EFFORT_REQUESTED_VALUES: readonly EffortRequested[] = ["low", "high", "xhigh", "ultra", "auto"];
export const EFFORT_RESOLVED_VALUES: readonly EffortResolved[] = ["low", "high", "xhigh", "ultra"];

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export const SEVERITY_VALUES: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

export type Verification = "verified" | "strong_evidence" | "needs_review";
export const VERIFICATION_VALUES: readonly Verification[] = ["verified", "strong_evidence", "needs_review"];

export type TokenSource = "exact" | "estimated" | "unavailable";
export type WorkspaceKind = "personal" | "team";
export type MembershipRole = "member" | "workspace_admin";

export type FindingStatus =
  | "open"
  | "fix_suggested"
  | "fix_applied"
  | "fixed_verified"
  | "accepted_risk"
  | "false_positive";

export type EvidenceKind =
  | "source"
  | "runtime"
  | "identity_differential"
  | "configuration"
  | "dependency"
  | "other";

export interface TokenUsage {
  /** Provenance is mandatory. Never fabricate an exact count. */
  source: TokenSource;
  count?: number;
  estimator?: string;
}

export interface AgentMetadata {
  name: string;
  version?: string;
  model?: string;
}

export interface HostEnvironment {
  osFamily: string;
  arch: string;
  runtimeVersion?: string;
  cliVersion?: string;
  isolatedRuntimeAvailable?: boolean;
}

export interface AuthorizedExternalTarget {
  target: string;
  authorized: true;
  authorizedAt?: string;
  /** How the human confirmed authorization for this exact target. */
  method?: "interactive_confirmation" | "preauthorized_project_config";
}

export interface FindingEvidence {
  kind: EvidenceKind;
  description: string;
  snippet?: string;
  location?: string;
  redacted?: boolean;
}

export interface SecretReference {
  label: string;
  kind: string;
  /** Local HMAC fingerprint. Never the raw value. */
  fingerprint: string;
  location?: string;
}

export interface FixHistoryEntry {
  at: string;
  action: "suggested" | "applied" | "verified" | "verification_failed" | "reverted";
  verified: boolean;
  changedFiles?: string[];
  note?: string;
}

export interface AffectedComponent {
  component: string;
  file?: string;
  lineStart?: number;
  lineEnd?: number;
  route?: string;
  origin?: string;
}

export interface Finding {
  id: string;
  title: string;
  category: string;
  taxonomy?: string[];
  severity: Severity;
  verification: Verification;
  summary: string;
  impact: string;
  affected: AffectedComponent;
  evidence: FindingEvidence[];
  remediation: string;
  verificationPlan: string;
  reproduction?: string;
  references?: string[];
  /** Stable dedupe identity assigned by the CLI, not by the agent. */
  fingerprint?: string;
  corroboration?: FindingEvidence[];
  secretReferences?: SecretReference[];
  status?: FindingStatus;
  fixedAt?: string;
  fixHistory?: FixHistoryEntry[];
  firstSeenAt?: string;
  tags?: string[];
}

export type ScanPhase =
  | "preflight"
  | "scope"
  | "discovery"
  | "source_review"
  | "runtime_validation"
  | "access_control"
  | "validation"
  | "reporting";

export const SCAN_PHASES: readonly ScanPhase[] = [
  "preflight",
  "scope",
  "discovery",
  "source_review",
  "runtime_validation",
  "access_control",
  "validation",
  "reporting"
];

export type PhaseState = "pending" | "running" | "complete" | "skipped";

export interface PhaseRecord {
  phase: ScanPhase;
  state: PhaseState;
  startedAt?: string;
  completedAt?: string;
  durationMs?: number;
  note?: string;
}

export interface StackSummary {
  languages: string[];
  frameworks: string[];
  packageManagers: string[];
  services: string[];
}

export interface EffortProfile {
  /** Resolved policy knobs. Effort is a policy profile, never a token quota. */
  reasoningPasses: number;
  validationPasses: number;
  maxParallelInvestigations: number;
  wallClockBudgetMs: number;
  falsePositiveChallengePass: boolean;
  identityMatrixDepth: 0 | 1 | 2 | 3;
  breadth: "focused" | "broad" | "comprehensive";
}

export interface CoverageArea {
  area: string;
  assessed: boolean;
  method?: string;
  note?: string;
}

export interface AuthorizationSummary {
  destructiveActionsAllowed: false;
  prohibitedActions: readonly string[];
  externalTargetAuthorization: "exact_origin_only";
  localTargetsInScope: boolean;
  notes?: string[];
}

export interface ReportSummary {
  findingCount: number;
  severityCounts: Record<Severity, number>;
  verificationCounts: Record<Verification, number>;
  candidateCount?: number;
  duplicateCount?: number;
  fixedCount?: number;
}

export interface ScanMetadata {
  effortRequested: EffortRequested;
  effortResolved: EffortResolved;
  effortProfile?: EffortProfile;
  startedAt?: string;
  completedAt?: string;
  durationMs: number;
  agent: AgentMetadata;
  host?: HostEnvironment;
  tokenUsage: TokenUsage;
  scope: { localTargets: string[]; externalTargets: AuthorizedExternalTarget[] };
  phases?: PhaseRecord[];
  stack?: StackSummary;
}

export interface ScanReport {
  schemaVersion: "1.0.0";
  id: string;
  cloudReportId?: string;
  generatedAt: string;
  project: { name: string; workspaceKind: WorkspaceKind; workspaceName?: string; repositoryLabel?: string };
  scan: ScanMetadata;
  authorization?: AuthorizationSummary;
  summary: ReportSummary;
  findings: Finding[];
  coverage: string[];
  coverageAreas?: CoverageArea[];
  limitations: string[];
  methodologyVersion?: string;
}

export type ScanEventType =
  | "report_created"
  | "phase_started"
  | "phase_completed"
  | "aggregate_updated"
  | "warning_safe"
  | "scan_completed"
  | "scan_failed";

export interface SafeScanEvent {
  eventId: string;
  reportId: string;
  type: ScanEventType;
  occurredAt: string;
  phase?: ScanPhase;
  safeCode?: string;
  message?: string;
  durationMs?: number;
  aggregate?: Partial<Record<"candidateCount" | "validatedCount" | Severity, number>>;
}

export interface SyncQuotaWindow {
  used: number;
  limit: number;
  resetsAt: string;
}

export interface SyncQuota {
  eligible: boolean;
  daily: SyncQuotaWindow;
  weekly: SyncQuotaWindow;
  blockedBy?: "daily" | "weekly" | "both";
  retentionDays: number;
  plan: PlanId;
}

export type PlanId = "free" | "pro" | "team" | "enterprise";

export type LocalCloudState =
  | "not_requested"
  | "quota_blocked"
  | "live"
  | "finalizing"
  | "synced"
  | "sync_failed";

export type ScanState =
  | "created"
  | "preflight"
  | "scope"
  | "discovery"
  | "assessment"
  | "validation"
  | "reporting"
  | "complete"
  | "cancelled"
  | "failed"
  | "policy_blocked";
