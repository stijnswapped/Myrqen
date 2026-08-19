import type {
  AgentMetadata,
  EffortRequested,
  EffortResolved,
  HostEnvironment,
  PlanId,
  ReportSummary,
  SafeScanEvent,
  Severity,
  SyncQuota,
  TokenUsage,
  Verification,
  WorkspaceKind
} from "./domain.js";
import type { ProjectionPolicy, ShareMode, SharePrincipalRule } from "./share.js";

export const API_PREFIX = "/api/v1";

export type ApiErrorCode =
  | "BAD_REQUEST"
  | "VALIDATION_FAILED"
  | "UNAUTHENTICATED"
  | "FORBIDDEN"
  | "NOT_FOUND"
  | "CONFLICT"
  | "RATE_LIMITED"
  | "INTERNAL"
  | "DEVICE_LINK_EXPIRED"
  | "DEVICE_LINK_ALREADY_CONSUMED"
  | "DEVICE_LINK_NOT_APPROVED"
  | "DEVICE_REVOKED"
  | "SYNC_DAILY_LIMIT_REACHED"
  | "SYNC_WEEKLY_LIMIT_REACHED"
  | "REPORT_EXPIRED"
  | "REPORT_SCHEMA_UNSUPPORTED"
  | "UNSAFE_PAYLOAD_REJECTED"
  | "SHARE_PASSWORD_REQUIRED"
  | "SHARE_NOT_AVAILABLE"
  | "CLIENT_VERSION_REVOKED"
  | "CLIENT_VERSION_TOO_OLD"
  | "SUPPORT_GRANT_REQUIRED";

export interface ApiError {
  error: {
    code: ApiErrorCode;
    message: string;
    requestId: string;
    details?: Record<string, unknown>;
  };
}

/* ---------- auth ---------- */

export interface SignupRequest {
  email: string;
  password: string;
}

export interface SignupResponse {
  userId: string;
  personalWorkspaceId: string;
  recoveryCodes: string[];
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface RecoveryLoginRequest {
  email: string;
  recoveryCode: string;
  newPassword: string;
}

/* ---------- device link ---------- */

export interface CreateDeviceLinkRequest {
  deviceName: string;
  clientVersion: string;
  osFamily: string;
  arch: string;
  /** SHA-256 of the CLI-held verifier, base64url. The verifier itself never leaves the device until exchange. */
  verifierHash: string;
}

export interface CreateDeviceLinkResponse {
  publicRequestId: string;
  approvalUrl: string;
  expiresAt: string;
  pollIntervalMs: number;
}

export interface DeviceLinkStatusResponse {
  state: "pending" | "approved" | "consumed" | "expired";
}

export interface ExchangeDeviceLinkRequest {
  verifier: string;
}

export interface ExchangeDeviceLinkResponse {
  deviceId: string;
  deviceName: string;
  /** Returned exactly once. Stored server-side only as a hash. */
  deviceToken: string;
  userId: string;
  email: string;
  apiBaseUrl: string;
}

/* ---------- workspace / project ---------- */

export interface WorkspaceSummary {
  id: string;
  kind: WorkspaceKind;
  name: string;
  role: "owner" | "member" | "workspace_admin";
  plan: PlanId;
}

export interface ProjectSummary {
  id: string;
  workspaceId: string;
  workspaceName: string;
  workspaceKind: WorkspaceKind;
  name: string;
  createdAt: string;
  lastReportAt?: string;
  lastReportId?: string;
  severityCounts?: Record<Severity, number>;
}

export interface CreateProjectRequest {
  /** Explicit. Never inferred from a repository name. */
  workspaceId: string;
  name: string;
  bindingPublicId: string;
}

/* ---------- sync ---------- */

export interface CreateReportRequest {
  workspaceId: string;
  projectId: string;
  localReportId: string;
  effortRequested: EffortRequested;
  effortResolved?: EffortResolved;
  agent: AgentMetadata;
  host?: HostEnvironment;
  projectName: string;
}

export interface CreateReportResponse {
  reportId: string;
  reportUrl: string;
  state: "live";
  expiresAt: string;
  quota: SyncQuota;
}

export interface ProgressRequest {
  events: SafeScanEvent[];
}

export interface ProgressResponse {
  accepted: number;
  rejected: number;
}

export interface UploadIntentRequest {
  byteLength: number;
  sha256: string;
}

export interface UploadIntentResponse {
  uploadId: string;
  /** Server-mediated upload endpoint. Object ACLs are never the authorization source. */
  uploadUrl: string;
  method: "PUT";
  headers: Record<string, string>;
  expiresAt: string;
}

export interface FinalizeReportRequest {
  uploadId: string;
  sha256: string;
  schemaVersion: string;
  summary: ReportSummary;
  durationMs: number;
  tokenUsage: TokenUsage;
  effortResolved: EffortResolved;
  /**
   * The host agent and model are often only known after the scan starts, so the
   * final values replace whatever the report shell was created with.
   */
  agent?: AgentMetadata;
}

export interface FinalizeReportResponse {
  reportId: string;
  state: "complete";
  reportUrl: string;
  expiresAt: string;
}

export interface ReportListItem {
  id: string;
  projectId: string;
  projectName: string;
  workspaceId: string;
  workspaceName: string;
  workspaceKind: WorkspaceKind;
  state: string;
  effortRequested: string;
  effortResolved?: string;
  agentName?: string;
  modelName?: string;
  durationMs?: number;
  tokenCount?: number;
  tokenSource: TokenUsage["source"];
  summary?: ReportSummary;
  syncCreatedAt: string;
  expiresAt: string;
  createdLocallyAt?: string;
}

/* ---------- shares ---------- */

export interface CreateShareRequest {
  mode: ShareMode;
  password?: string;
  expiresAt?: string;
  anonymousAllowed?: boolean;
  defaultPolicy: ProjectionPolicy;
  principals: Array<Omit<SharePrincipalRule, "id">>;
}

export interface CreateShareResponse {
  shareId: string;
  slug: string;
  url: string;
}

/* ---------- admin ---------- */

export interface FunnelStage {
  key: string;
  label: string;
  count: number;
  conversionFromPrevious: number | null;
  medianElapsedMsFromPrevious: number | null;
}

export interface FunnelResponse {
  stages: FunnelStage[];
  cohortSuppressed: boolean;
  minimumCohortSize: number;
  filters: Record<string, string | undefined>;
}

export interface ScanMetricsRow {
  agentName: string;
  modelName: string;
  effortResolved: string;
  scans: number;
  completed: number;
  failed: number;
  cancelled: number;
  durationP50Ms: number | null;
  durationP95Ms: number | null;
  tokenExactAvg: number | null;
  tokenEstimatedAvg: number | null;
  tokenUnavailableCount: number;
  validatedFindings: number;
  totalFindings: number;
}

export interface ScanMetricsResponse {
  rows: ScanMetricsRow[];
  effortDistribution: Record<string, number>;
  syncDecision: { offered: number; accepted: number; declined: number; quotaBlocked: number };
}

export interface CreateSupportGrantRequest {
  reportId: string;
  reason: string;
  expiresInMinutes: number;
}

export interface SupportGrantSummary {
  id: string;
  reportId: string;
  adminUserId: string;
  adminEmail?: string;
  reason: string;
  createdAt: string;
  expiresAt: string;
  revokedAt?: string;
  useCount: number;
}

export interface VerificationCountsResponse {
  counts: Record<Verification, number>;
}
