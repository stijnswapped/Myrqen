import crypto from "node:crypto";
import type { SafeScanEvent, ScanEventType, ScanPhase, Severity } from "@myrqen/contracts";
import { validateScanEvent } from "@myrqen/contracts";
import { assertSafeProgressMessage } from "./redaction.js";

const SAFE_KEYS = new Set([
  "eventId",
  "reportId",
  "type",
  "occurredAt",
  "phase",
  "safeCode",
  "message",
  "durationMs",
  "aggregate"
]);

const SAFE_AGGREGATE_KEYS = new Set([
  "candidateCount",
  "validatedCount",
  "critical",
  "high",
  "medium",
  "low",
  "info"
]);

/**
 * Allowlisted status copy. The scanner may not invent free-form progress text
 * for the cloud; it selects a code, and the message is derived from it.
 */
export const SAFE_STATUS_CODES: Readonly<Record<string, string>> = Object.freeze({
  PREFLIGHT_STARTED: "Checking project and authorization boundaries",
  SCOPE_RESOLVED: "Scope resolved",
  RUNTIME_UNAVAILABLE: "No local runtime reachable; static coverage only",
  ISOLATION_UNAVAILABLE: "Isolated runtime checks unavailable on this machine",
  MAPPING_APPLICATION: "Mapping application surface",
  REVIEWING_SOURCE: "Reviewing source, configuration, and dependencies",
  VALIDATING_CANDIDATES: "Validating candidate findings",
  COMPARING_IDENTITIES: "Comparing access-control identities",
  CHALLENGING_FINDINGS: "Challenging findings for false positives",
  GENERATING_REPORT: "Generating report",
  EXTERNAL_TARGET_AUTHORIZED: "An external target was authorized by the operator",
  EXTERNAL_TARGET_DECLINED: "An external target was not authorized; skipped",
  PROMPT_INJECTION_OBSERVED: "Assessed content attempted to change scanner instructions; ignored",
  BUDGET_REACHED: "Effort budget reached; finalizing",
  SCAN_COMPLETE: "Scan complete",
  SCAN_FAILED: "Scan failed"
});

/**
 * Runtime guard layered on top of JSON-schema validation. Applied on the
 * sending side (CLI) and again on the receiving side (API).
 */
export function assertLiveEventSafe(event: SafeScanEvent & Record<string, unknown>): void {
  for (const key of Object.keys(event)) {
    if (!SAFE_KEYS.has(key)) throw new Error(`Unknown or unsafe live event field: ${key}`);
  }
  if (event.aggregate) {
    for (const key of Object.keys(event.aggregate)) {
      if (!SAFE_AGGREGATE_KEYS.has(key)) throw new Error(`Unknown or unsafe aggregate field: ${key}`);
    }
  }
  if (event.safeCode !== undefined) {
    if (!/^[A-Z0-9_]{1,80}$/.test(event.safeCode)) throw new Error("Invalid safeCode format.");
    if (!(event.safeCode in SAFE_STATUS_CODES)) throw new Error(`safeCode "${event.safeCode}" is not allowlisted.`);
  }
  /*
   * The allowlist above only described what the message may be; nothing checked
   * that it was. A device could put any 300 characters in `message` and the API
   * would store and broadcast them, which is how a project's own secret reached
   * the cloud progress stream in the acceptance suite: the heuristic scrubber
   * below cannot recognise a value it has never seen, and the server has no copy
   * of the project's secrets to compare against.
   *
   * So the message is now required to be exactly the text its code resolves to.
   * `buildSafeEvent` has always derived it that way, so nothing that goes
   * through the product changes — but free-form text can no longer be smuggled
   * through this field at all, which is a guarantee rather than a filter.
   */
  if (event.message !== undefined) {
    const allowlisted = event.safeCode === undefined ? undefined : SAFE_STATUS_CODES[event.safeCode];
    if (allowlisted === undefined) {
      throw new Error("A progress message is only allowed alongside an allowlisted safeCode.");
    }
    if (event.message !== allowlisted) {
      throw new Error("Progress message does not match the text its safeCode resolves to.");
    }
  }
  assertSafeProgressMessage(event.message);
  if (event.reportId.length > 128 || event.eventId.length > 128) throw new Error("Event identifier too long.");

  const schema = validateScanEvent(event);
  if (!schema.valid) throw new Error("Live event failed schemas/scan-event.schema.json validation.");
}

export interface BuildEventInput {
  reportId: string;
  type: ScanEventType;
  phase?: ScanPhase;
  safeCode?: keyof typeof SAFE_STATUS_CODES | string;
  durationMs?: number;
  aggregate?: Partial<Record<"candidateCount" | "validatedCount" | Severity, number>>;
  at?: Date;
}

/** Build an event whose message can only come from the allowlist. */
export function buildSafeEvent(input: BuildEventInput): SafeScanEvent {
  const event: SafeScanEvent = {
    eventId: `evt_${crypto.randomUUID()}`,
    reportId: input.reportId,
    type: input.type,
    occurredAt: (input.at ?? new Date()).toISOString()
  };
  if (input.phase) event.phase = input.phase;
  if (input.safeCode) {
    event.safeCode = input.safeCode;
    const message = SAFE_STATUS_CODES[input.safeCode];
    if (message) event.message = message;
  }
  if (typeof input.durationMs === "number") event.durationMs = Math.max(0, Math.round(input.durationMs));
  if (input.aggregate) event.aggregate = input.aggregate;
  assertLiveEventSafe(event as SafeScanEvent & Record<string, unknown>);
  return event;
}
