import type { EffortRequested, EffortResolved, TokenSource } from "@myrqen/contracts";

/**
 * Every name here has a live emitter. A declared name that nothing emits renders
 * as a real zero on the platform dashboard, which an operator reads as "nobody
 * did this" rather than "this is not instrumented", so the taxonomy carries only
 * what is actually collected. Share opens and denials are counted from
 * share_access_events, which records them with the outcome and principal type.
 */
export const PRODUCT_EVENT_NAMES = [
  "account_created",
  "recovery_codes_confirmed",
  "device_link_started",
  "device_link_approved",
  "device_link_completed",
  "onboarding_completed",
  "onboarding_skipped",
  "project_bound",
  "scan_started",
  "scan_completed",
  "scan_cancelled",
  "sync_offered",
  "sync_accepted",
  "sync_declined",
  "sync_quota_blocked",
  "cloud_report_created",
  "fix_prompt_copied",
  "fix_apply_started",
  "fix_verify_completed",
  "share_created",
  "update_check_completed"
] as const;

export type ProductEventName = (typeof PRODUCT_EVENT_NAMES)[number];

/** Only these metric keys are accepted. There is no free-form properties bag. */
export const ALLOWED_METRIC_KEYS = [
  "duration_ms",
  "phase_preflight_ms",
  "phase_scope_ms",
  "phase_discovery_ms",
  "phase_source_review_ms",
  "phase_runtime_validation_ms",
  "phase_access_control_ms",
  "phase_validation_ms",
  "phase_reporting_ms",
  "candidate_count",
  "validated_count",
  "duplicate_count",
  "severity_critical",
  "severity_high",
  "severity_medium",
  "severity_low",
  "severity_info",
  "verification_verified",
  "verification_strong_evidence",
  "verification_needs_review",
  "category_count",
  "token_count",
  "token_source",
  "token_estimator",
  "result_code",
  "isolated_runtime_available",
  "external_authorized_target_count",
  "local_target_count",
  "share_mode",
  "share_principal_count",
  "quota_blocked_by",
  "fix_verified",
  "agent_channel",
  "update_state",
  "denial_reason",
  "projection_finding_count"
] as const;

export type AllowedMetricKey = (typeof ALLOWED_METRIC_KEYS)[number];
export type MetricValue = number | boolean | string | null;

export interface ProductEventEnvelope {
  eventId: string;
  name: ProductEventName;
  version: 1;
  occurredAt: string;
  /** Internal identifiers only. Email addresses never enter this stream. */
  userId?: string;
  workspaceId?: string;
  projectId?: string;
  reportId?: string;
  /** Pre-account bootstrap only, where no user id exists yet. */
  anonymousSessionId?: string;
  client: "web" | "cli" | "worker";
  clientVersion?: string;
  osFamily?: string;
  arch?: string;
  agentName?: string;
  agentVersion?: string;
  modelName?: string;
  effortRequested?: EffortRequested;
  effortResolved?: EffortResolved;
  metrics?: Partial<Record<AllowedMetricKey, MetricValue>>;
}

const ENVELOPE_KEYS = new Set<string>([
  "eventId",
  "name",
  "version",
  "occurredAt",
  "userId",
  "workspaceId",
  "projectId",
  "reportId",
  "anonymousSessionId",
  "client",
  "clientVersion",
  "osFamily",
  "arch",
  "agentName",
  "agentVersion",
  "modelName",
  "effortRequested",
  "effortResolved",
  "metrics"
]);

const FORBIDDEN_KEY = /(source|snippet|code|secret|password|authorization|cookie|evidence|prompt|requestbody|responsebody|reporttext|finding_?title|description|remediation|email|repository|filepath|path|url|origin|route|stack)/i;

/**
 * Dimensions are bounded labels, not free text. Field-name allowlisting alone
 * does not stop a naive or compromised integration from passing a repository
 * path, an email address, or a slab of report prose as an agent or model name,
 * and product_events is the store the platform-admin dashboard presents as
 * operational metadata only. A version, OS family, or architecture is always one
 * token; only an agent or model name legitimately contains a space.
 */
const TOKEN_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._+-]*$/;
const TWO_WORD_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._+-]*(?: [A-Za-z0-9][A-Za-z0-9._+-]*)?$/;
const MAX_STRING_METRIC_LENGTH = 64;

const DIMENSION_RULES = [
  { field: "clientVersion", maxLength: 40, shape: "token" },
  { field: "osFamily", maxLength: 40, shape: "token" },
  { field: "arch", maxLength: 20, shape: "token" },
  { field: "agentVersion", maxLength: 40, shape: "token" },
  { field: "agentName", maxLength: 64, shape: "label" },
  { field: "modelName", maxLength: 64, shape: "label" }
] as const;

const MAX_IDENTIFIER_LENGTH = 64;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;
const IDENTIFIER_FIELDS = ["userId", "workspaceId", "projectId", "reportId", "anonymousSessionId"] as const;

const TOKEN_SOURCES = ["exact", "estimated", "unavailable"] as const;

/**
 * Token counts are declared by the host agent and cannot be verified from here.
 * A count above this ceiling is not a measurement of any real scan, so accepting
 * one would let a single integration corrupt the exact and estimated columns the
 * dashboard presents as trustworthy.
 */
const MAX_TOKEN_COUNT = 50_000_000;

export class AnalyticsSafetyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AnalyticsSafetyError";
  }
}

function isBounded(value: string, maxLength: number, shape: "token" | "label"): boolean {
  if (value.length === 0 || value.length > maxLength) return false;
  return shape === "token" ? TOKEN_PATTERN.test(value) : TWO_WORD_PATTERN.test(value);
}

function assertMetricsSafe(metrics: unknown): void {
  if (!metrics || typeof metrics !== "object" || Array.isArray(metrics)) {
    throw new AnalyticsSafetyError("Analytics metrics must be a flat object.");
  }
  const record = metrics as Record<string, unknown>;

  for (const [key, value] of Object.entries(record)) {
    if (!(ALLOWED_METRIC_KEYS as readonly string[]).includes(key)) {
      throw new AnalyticsSafetyError(`Forbidden analytics metric: ${key}`);
    }
    if (value === null) continue;
    const type = typeof value;
    if (type !== "number" && type !== "boolean" && type !== "string") {
      throw new AnalyticsSafetyError(`Analytics metric ${key} must be a scalar.`);
    }
    if (type === "string") {
      const text = value as string;
      if (text.length > MAX_STRING_METRIC_LENGTH) {
        throw new AnalyticsSafetyError(`Analytics metric ${key} exceeds the safe string length.`);
      }
      if (!isBounded(text, MAX_STRING_METRIC_LENGTH, "token")) {
        throw new AnalyticsSafetyError(`Analytics metric ${key} must be a short code, not free text.`);
      }
    }
  }

  if (record.token_source !== undefined && record.token_source !== null) {
    if (!(TOKEN_SOURCES as readonly string[]).includes(String(record.token_source))) {
      throw new AnalyticsSafetyError("Analytics token_source must be exact, estimated, or unavailable.");
    }
  }

  const tokenCount = record.token_count;
  if (tokenCount !== undefined && tokenCount !== null) {
    if (typeof tokenCount !== "number" || !Number.isInteger(tokenCount) || tokenCount < 0) {
      throw new AnalyticsSafetyError("Analytics token_count must be a whole number of tokens.");
    }
    if (tokenCount > MAX_TOKEN_COUNT) {
      throw new AnalyticsSafetyError(
        `Analytics token_count above ${MAX_TOKEN_COUNT} is not a plausible scan measurement.`
      );
    }
    if (record.token_source === undefined || record.token_source === null || record.token_source === "unavailable") {
      throw new AnalyticsSafetyError("Analytics token_count must travel with the token_source it came from.");
    }
  }

  if (record.token_estimator !== undefined && record.token_estimator !== null && record.token_source !== "estimated") {
    throw new AnalyticsSafetyError("Analytics token_estimator only describes an estimated count.");
  }
}

/**
 * Boundary D. Product analytics are a separate stream from report content. This
 * check rejects report prose, source, secrets, and any unknown field rather than
 * trying to sanitize it.
 */
export function assertAnalyticsEventSafe(event: unknown): asserts event is ProductEventEnvelope {
  if (!event || typeof event !== "object") throw new AnalyticsSafetyError("Analytics event must be an object.");
  const candidate = event as Record<string, unknown>;

  for (const key of Object.keys(candidate)) {
    if (!ENVELOPE_KEYS.has(key)) throw new AnalyticsSafetyError(`Forbidden analytics field: ${key}`);
    if (FORBIDDEN_KEY.test(key)) throw new AnalyticsSafetyError(`Forbidden analytics field: ${key}`);
  }

  if (typeof candidate.name !== "string" || !(PRODUCT_EVENT_NAMES as readonly string[]).includes(candidate.name)) {
    throw new AnalyticsSafetyError(`Unknown analytics event name: ${String(candidate.name)}`);
  }
  if (candidate.version !== 1) throw new AnalyticsSafetyError("Analytics event version must be 1.");
  if (typeof candidate.client !== "string" || !["web", "cli", "worker"].includes(candidate.client)) {
    throw new AnalyticsSafetyError("Analytics client must be web, cli, or worker.");
  }
  if (typeof candidate.occurredAt !== "string" || Number.isNaN(Date.parse(candidate.occurredAt))) {
    throw new AnalyticsSafetyError("Analytics occurredAt must be an ISO instant.");
  }

  if (candidate.metrics !== undefined) assertMetricsSafe(candidate.metrics);

  for (const field of IDENTIFIER_FIELDS) {
    const value = candidate[field];
    if (value === undefined) continue;
    if (typeof value !== "string" || !IDENTIFIER_PATTERN.test(value)) {
      throw new AnalyticsSafetyError(
        `Analytics ${field} must be an internal identifier of at most ${MAX_IDENTIFIER_LENGTH} characters, not an email address or a path.`
      );
    }
  }

  for (const rule of DIMENSION_RULES) {
    const value = candidate[rule.field];
    if (value === undefined) continue;
    if (typeof value !== "string" || !isBounded(value, rule.maxLength, rule.shape)) {
      throw new AnalyticsSafetyError(
        rule.shape === "token"
          ? `Analytics ${rule.field} must be one token of at most ${rule.maxLength} characters (letters, digits, and . _ + -), not free text.`
          : `Analytics ${rule.field} must be at most ${rule.maxLength} characters and at most two words (letters, digits, and . _ + -), not free text.`
      );
    }
  }
}

export interface TokenMetrics {
  token_count?: number;
  token_source: TokenSource;
  token_estimator?: string;
}

/** Token counts always travel with their provenance. */
export function tokenMetrics(usage: { source: TokenSource; count?: number; estimator?: string }): TokenMetrics {
  const metrics: TokenMetrics = { token_source: usage.source };
  if (usage.source !== "unavailable" && typeof usage.count === "number") metrics.token_count = usage.count;
  if (usage.source === "estimated" && usage.estimator) metrics.token_estimator = usage.estimator;
  return metrics;
}

export function createEvent(
  input: Omit<ProductEventEnvelope, "eventId" | "version" | "occurredAt"> & { occurredAt?: string; eventId?: string }
): ProductEventEnvelope {
  const event: ProductEventEnvelope = {
    eventId: input.eventId ?? `pev_${crypto.randomUUID()}`,
    version: 1,
    occurredAt: input.occurredAt ?? new Date().toISOString(),
    name: input.name,
    client: input.client
  };
  for (const key of [
    "userId",
    "workspaceId",
    "projectId",
    "reportId",
    "anonymousSessionId",
    "clientVersion",
    "osFamily",
    "arch",
    "agentName",
    "agentVersion",
    "modelName",
    "effortRequested",
    "effortResolved",
    "metrics"
  ] as const) {
    const value = input[key];
    if (value !== undefined) (event as unknown as Record<string, unknown>)[key] = value;
  }
  assertAnalyticsEventSafe(event);
  return event;
}
