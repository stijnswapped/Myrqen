import crypto from "node:crypto";
import { BRAND, CLI_VERSION } from "@myrqen/brand";
import type { SafeScanEvent, ScanEventType, ScanPhase, ScanReport, Severity } from "@myrqen/contracts";
import { buildSafeEvent } from "@myrqen/policy";
import { ApiClient, ApiRequestError } from "../api/client.js";
import type { SessionState } from "./state.js";
import { saveSession } from "./state.js";
import { warn } from "../ui/output.js";

export interface ProgressInput {
  type: ScanEventType;
  phase?: ScanPhase;
  safeCode?: string;
  durationMs?: number;
  aggregate?: Partial<Record<"candidateCount" | "validatedCount" | Severity, number>>;
}

/**
 * Progress is emitted only for a scan that opted into sync. A failure to deliver
 * an event never fails the scan and never blocks local reporting.
 */
export async function emitProgress(
  state: SessionState,
  client: ApiClient | null,
  input: ProgressInput
): Promise<boolean> {
  if (state.cloud.state !== "live" || !state.cloud.reportId || !client?.authenticated) return false;
  let event: SafeScanEvent;
  try {
    event = buildSafeEvent({ reportId: state.cloud.reportId, ...input });
  } catch (error) {
    // A refused event is a policy success: it means nothing unsafe was sent.
    warn(`Progress event withheld: ${error instanceof Error ? error.message : "unsafe payload"}`);
    return false;
  }
  try {
    await client.sendProgress(state.cloud.reportId, [event]);
    return true;
  } catch (error) {
    if (error instanceof ApiRequestError && error.code === "REPORT_EXPIRED") {
      state.cloud.state = "sync_failed";
      state.cloud.lastError = error.message;
      await saveSession(state);
    }
    return false;
  }
}

export interface FinalizeOutcome {
  synced: boolean;
  reportUrl?: string;
  error?: string;
}

/**
 * Upload and finalize. A cloud failure preserves the complete local report and a
 * retryable state; it never deletes or corrupts local results.
 */
export async function finalizeCloudReport(
  state: SessionState,
  client: ApiClient,
  report: ScanReport
): Promise<FinalizeOutcome> {
  if (!state.cloud.reportId) return { synced: false, error: "This scan has no cloud report." };

  const body = Buffer.from(`${JSON.stringify(report, null, 2)}\n`, "utf8");
  const sha256 = crypto.createHash("sha256").update(body).digest("hex");

  try {
    const intent = await client.uploadIntent(state.cloud.reportId, sha256, body.byteLength);
    await client.uploadBody(intent.uploadUrl, body);
    const finalized = await client.finalizeReport(state.cloud.reportId, {
      uploadId: intent.uploadId,
      sha256,
      schemaVersion: report.schemaVersion,
      summary: report.summary,
      durationMs: report.scan.durationMs,
      tokenUsage: report.scan.tokenUsage,
      effortResolved: report.scan.effortResolved,
      agent: report.scan.agent
    });
    state.cloud.state = "synced";
    state.cloud.reportUrl = finalized.reportUrl;
    state.cloud.expiresAt = finalized.expiresAt;
    delete state.cloud.lastError;
    await saveSession(state);
    return { synced: true, reportUrl: finalized.reportUrl };
  } catch (error) {
    const message = error instanceof Error ? error.message : "The report could not be uploaded.";
    state.cloud.state = "sync_failed";
    state.cloud.lastError = message;
    await saveSession(state);
    return { synced: false, error: message };
  }
}

export function retryHint(state: SessionState): string {
  return `The local report is complete. Retry the upload with "${BRAND.cliName} sync ${state.localReportId}".`;
}

export function hostEnvironment(isolatedRuntimeAvailable: boolean) {
  return {
    osFamily: process.platform,
    arch: process.arch,
    runtimeVersion: `node ${process.versions.node}`,
    cliVersion: CLI_VERSION,
    isolatedRuntimeAvailable
  };
}

export const SAFE_PHASE_CODES: Readonly<Record<ScanPhase, string>> = Object.freeze({
  preflight: "PREFLIGHT_STARTED",
  scope: "SCOPE_RESOLVED",
  discovery: "MAPPING_APPLICATION",
  source_review: "REVIEWING_SOURCE",
  runtime_validation: "VALIDATING_CANDIDATES",
  access_control: "COMPARING_IDENTITIES",
  validation: "CHALLENGING_FINDINGS",
  reporting: "GENERATING_REPORT"
});
