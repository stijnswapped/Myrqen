import fs from "node:fs/promises";
import path from "node:path";
import { BRAND } from "@myrqen/brand";
import type { ScanReport } from "@myrqen/contracts";
import { validateReport } from "@myrqen/contracts";
import { describeQuotaBlock } from "@myrqen/policy";
import { resolveClient } from "../api/client.js";
import { reportDirectory } from "../config/paths.js";
import { findRepoRoot } from "../discovery/project.js";
import { blank, bullet, field, heading, json, style, warn, write } from "../ui/output.js";
import { createCloudShell } from "../session/start.js";
import { finalizeCloudReport, retryHint } from "../session/sync.js";
import { listSessions, loadSession, saveSession } from "../session/state.js";

export async function reportsCommand(options: { asJson?: boolean } = {}): Promise<void> {
  const repoRoot = await findRepoRoot(process.cwd());
  const sessions = await listSessions(repoRoot);

  if (options.asJson) {
    json({
      reports: sessions.map((session) => ({
        localReportId: session.localReportId,
        project: session.project.name,
        state: session.state,
        createdAt: session.createdAt,
        findingCount: session.findings.length,
        cloud: session.cloud.state,
        cloudReportUrl: session.cloud.reportUrl,
        effort: session.effort.resolved
      }))
    });
    return;
  }

  heading("local reports");
  if (sessions.length === 0) {
    write(`No local reports in ${repoRoot}. Run "${BRAND.cliName} auto" to create one.`);
    return;
  }

  for (const session of sessions) {
    const verified = session.findings.filter((finding) => finding.verification === "verified").length;
    write(
      `${style.bold(session.localReportId)}  ${session.createdAt.slice(0, 16).replace("T", " ")}  ${session.state}`
    );
    bullet(
      `${session.project.name} · ${session.effort.resolved} effort · ${session.findings.length} findings (${verified} verified)`
    );
    bullet(
      session.cloud.state === "synced" || session.cloud.state === "live"
        ? `cloud: ${session.cloud.state} ${session.cloud.reportUrl ?? ""}`
        : `cloud: ${session.cloud.state}${session.cloud.reason ? ` — ${session.cloud.reason}` : ""}`
    );
  }
  blank();
  write(`Sync a local report later with "${BRAND.cliName} sync <local-report-id>".`);
}

async function readLocalReport(repoRoot: string, localReportId: string): Promise<ScanReport> {
  const file = path.join(reportDirectory(repoRoot, localReportId), "report.json");
  let raw: string;
  try {
    raw = await fs.readFile(file, "utf8");
  } catch {
    throw new Error(`No finalized local report was found at ${file}.`);
  }
  const parsed = validateReport(JSON.parse(raw));
  if (!parsed.valid || !parsed.value) {
    throw new Error(`The local report at ${file} does not match the supported report schema.`);
  }
  return parsed.value;
}

/**
 * Explicit later sync. It rechecks login, device, and quota, names the
 * destination, and never runs on its own after a reset.
 */
export async function syncCommand(localReportId: string, options: { asJson?: boolean } = {}): Promise<void> {
  const repoRoot = await findRepoRoot(process.cwd());
  const session = await loadSession(repoRoot, localReportId);
  if (!session) throw new Error(`No local session ${localReportId} was found in ${repoRoot}.`);

  const report = await readLocalReport(repoRoot, localReportId);
  const { client, account } = await resolveClient();
  if (!client.authenticated || !account) {
    throw new Error(`This device is not linked. Run "${BRAND.cliName} login" first.`);
  }
  if (!session.project.workspaceId || !session.project.projectId) {
    throw new Error(
      `${localReportId} is not bound to a workspace. Run "${BRAND.cliName} workspace" to bind this repository, then sync again.`
    );
  }

  if (session.cloud.state === "synced") {
    write(`${localReportId} is already synced: ${session.cloud.reportUrl}`);
    return;
  }

  const quota = await client.syncQuota(session.project.workspaceId);
  heading("sync");
  field("Local report", localReportId);
  field(
    "Destination",
    `${session.project.workspaceName ?? session.project.workspaceId} (${session.project.workspaceKind}) · project ${session.project.projectId}`
  );
  field("Quota", `${quota.daily.used}/${quota.daily.limit} today · ${quota.weekly.used}/${quota.weekly.limit} this week`);

  if (!quota.eligible) {
    // Expected state, not a failure: say it once, plainly, on stdout.
    write(describeQuotaBlock(quota, BRAND.cliName, localReportId));
    write("Nothing was uploaded and the local report is unchanged.");
    return;
  }

  if (!session.cloud.reportId) {
    await createCloudShell(session, client);
    await saveSession(session);
  }
  if (session.cloud.state === "quota_blocked" || !session.cloud.reportId) {
    warn(session.cloud.reason ?? "The cloud report could not be created.");
    return;
  }

  const outcome = await finalizeCloudReport(session, client, report);
  if (options.asJson) {
    json({ localReportId, synced: outcome.synced, reportUrl: outcome.reportUrl, error: outcome.error });
    return;
  }
  if (outcome.synced) write(`${style.ok("Synced")} ${outcome.reportUrl}`);
  else {
    warn(outcome.error ?? "The report could not be uploaded.");
    write(retryHint(session));
  }
}
