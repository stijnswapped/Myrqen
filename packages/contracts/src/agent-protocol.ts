import type {
  AuthorizedExternalTarget,
  EffortProfile,
  EffortRequested,
  EffortResolved,
  Finding,
  LocalCloudState,
  ScanPhase,
  StackSummary,
  WorkspaceKind
} from "./domain.js";

/**
 * The host agent never invents scope, quota, or cloud state. It calls the local
 * CLI, receives this context, and works inside it. Everything the agent is
 * allowed to do is enumerated here.
 */
export interface SessionContext {
  contextVersion: 1;
  localReportId: string;
  sessionDir: string;
  createdAt: string;
  repositoryRoot: string;
  project: {
    name: string;
    workspaceKind: WorkspaceKind;
    workspaceName?: string;
    workspaceId?: string;
    projectId?: string;
    bindingSource: "team_committed" | "personal_local" | "unbound";
  };
  effort: {
    requested: EffortRequested;
    resolved: EffortResolved;
    profile: EffortProfile;
    rationale: string[];
  };
  scope: {
    localTargetPatterns: string[];
    discoveredLocalTargets: string[];
    authorizedExternalTargets: AuthorizedExternalTarget[];
    pendingExternalCandidates: string[];
  };
  policy: {
    destructiveActionsAllowed: false;
    prohibitedActions: readonly string[];
    externalTargetsRequireExactAuthorization: true;
    uploadFullRepository: false;
    untrustedContentRule: string;
  };
  stack: StackSummary;
  artifacts: {
    sessionFile: string;
    findingsFile: string;
    reportJson: string;
    reportHtml: string;
    reportMarkdown: string;
    reportSarif: string;
  };
  cloud: {
    state: LocalCloudState;
    reportId?: string;
    reportUrl?: string;
    reason?: string;
  };
  hostMetadataInstructions: string[];
  /**
   * What the CLI's own static pass already found, so the agent starts from
   * evidence instead of from an empty file list. Absent when the pass was
   * skipped.
   */
  staticPass?: {
    filesParsed: number;
    rulesRun: number;
    durationMs: number;
    candidatesRecorded: number;
    /** What the static pass could not see. The agent's job starts here. */
    notAssessed: string[];
  };
  nextSteps: string[];
}

export interface FindingSubmission {
  /** Agent-proposed finding. The CLI owns IDs, fingerprints, and dedupe. */
  title: string;
  category: string;
  taxonomy?: string[];
  severity: Finding["severity"];
  verification: Finding["verification"];
  summary: string;
  impact: string;
  affected: Finding["affected"];
  evidence: Finding["evidence"];
  remediation: string;
  verificationPlan: string;
  reproduction?: string;
  references?: string[];
  tags?: string[];
}

export interface FindingSubmissionResult {
  accepted: boolean;
  findingId?: string;
  deduplicatedInto?: string;
  action: "created" | "merged_as_corroboration" | "rejected";
  fingerprint?: string;
  warnings: string[];
  errors: string[];
  redactions: number;
}

export interface ExternalTargetDecision {
  target: string;
  normalizedOrigin: string;
  decision: "already_authorized" | "authorized" | "denied" | "local_no_authorization_needed";
  reason?: string;
}

export interface PhaseUpdateResult {
  phase: ScanPhase;
  state: "running" | "complete";
  cloudEventEmitted: boolean;
}

export interface SessionFinishResult {
  localReportId: string;
  files: { json: string; html: string; markdown: string; sarif: string };
  summary: { findingCount: number; validatedCount: number };
  cloud: { state: LocalCloudState; reportId?: string; reportUrl?: string; error?: string };
  warnings: string[];
}

export type AgentCommandName =
  | "session start"
  | "session context"
  | "session finish"
  | "session cancel"
  | "target authorize"
  | "finding submit"
  | "phase start"
  | "phase complete"
  | "note coverage"
  | "note limitation"
  | "metrics token"
  | "fix prompt"
  | "fix record";
