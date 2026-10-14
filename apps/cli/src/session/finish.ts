import fs from "node:fs/promises";
import path from "node:path";
import { BRAND } from "@myrqen/brand";
import type { ScanMetadata, ScanReport, SessionFinishResult } from "@myrqen/contracts";
import { buildReport, renderMarkdown, renderSarif, renderStandaloneHtml, type BaselineFile } from "@myrqen/report";
import { readBaselineFile } from "../commands/baseline.js";
import { redactDeep } from "@myrqen/policy";
import { resolveClient } from "../api/client.js";
import { reportDirectory } from "../config/paths.js";
import { blank, bullet, field, heading, json, style, write } from "../ui/output.js";
import { finalizeCloudReport, emitProgress, retryHint } from "./sync.js";
import type { SessionState } from "./state.js";
import { elapsedMs, loadKnownSecrets, markPhase, saveSession } from "./state.js";
import { track } from "../api/telemetry.js";
import { detectHostAgent, installedAgentIds, staticOnlySummary, verificationHints } from "../agent/host.js";
import { snapshotFromSession, stageTimings } from "../ui/progress.js";

export interface FinishOptions {
  state: SessionState;
  asJson?: boolean;
  cancelled?: boolean;
}

function coverageDefaults(state: SessionState): { coverage: string[]; limitations: string[] } {
  const coverage = [...state.coverage];
  const limitations = [...state.limitations];

  if (coverage.length === 0) {
    coverage.push("Repository, configuration, and dependency review of the in-scope source tree.");
  }
  if (state.scope.localTargets.length > 0 && state.stack.services.length > 0) {
    coverage.push(`Local runtime validation against ${state.stack.services.join(", ")}.`);
  } else {
    limitations.push(
      "No local service was reachable during this scan, so runtime validation and access-control comparison were limited."
    );
  }
  if (state.host.isolatedRuntimeAvailable === false) {
    limitations.push(
      "Some isolated runtime checks were skipped on this machine. Source, configuration, dependency, and available local-runtime checks still ran."
    );
  }
  if (state.scope.pendingExternalCandidates.length > 0) {
    limitations.push(
      `${state.scope.pendingExternalCandidates.length} external origin(s) referenced by this project were not authorized and were not tested.`
    );
  }
  if (state.scope.injectionSuggestedOrigins?.length > 0) {
    limitations.push(
      `${state.scope.injectionSuggestedOrigins.length} origin(s) were proposed only by project content that also tried to instruct the scanner. They were refused and not tested.`
    );
  }
  if (state.scope.deniedExternalTargets.length > 0) {
    limitations.push(
      `Authorization was declined for ${state.scope.deniedExternalTargets.length} external origin(s), which were skipped.`
    );
  }
  if (state.injectionObservations.length > 0) {
    coverage.push(
      `${state.injectionObservations.length} instruction-like passage(s) in project content were treated as untrusted data and did not change scope.`
    );
  }
  const blocked = state.actionLog.filter((entry) => !entry.allowed);
  if (blocked.length > 0) {
    limitations.push(
      `${blocked.length} proposed action(s) were blocked by safety policy and were replaced with non-destructive checks or recorded as unverified.`
    );
  }
  return { coverage, limitations };
}

function scanMetadata(state: SessionState, endedAt: Date): ScanMetadata {
  return {
    effortRequested: state.effort.requested,
    effortResolved: state.effort.resolved,
    effortProfile: state.effort.profile,
    startedAt: state.startedAt,
    completedAt: endedAt.toISOString(),
    durationMs: elapsedMs(state, endedAt),
    agent: state.agent,
    host: state.host,
    tokenUsage: state.tokenUsage,
    scope: {
      localTargets: state.stack.services.length > 0 ? state.stack.services : state.scope.localTargets,
      externalTargets: state.scope.authorizedExternalTargets
    },
    // The report is written as the last step of the reporting phase, so the copy
    // inside it records that phase as complete rather than frozen mid-run.
    phases: state.phases.map((phase) =>
      phase.phase === "reporting" && phase.state === "running"
        ? { ...phase, state: "complete" as const, completedAt: endedAt.toISOString(), durationMs: 0 }
        : phase
    ),
    stack: state.stack
  };
}

/** A committed baseline, if the project has one. A broken one is reported, never fatal. */
async function loadBaseline(repoRoot: string, warnings: string[]): Promise<BaselineFile | undefined> {
  try {
    return (await readBaselineFile(repoRoot)) ?? undefined;
  } catch (error) {
    warnings.push(`.myrqen/baseline.json was not used: ${error instanceof Error ? error.message : String(error)}`);
    return undefined;
  }
}

export interface LocalReportFiles {
  json: string;
  html: string;
  markdown: string;
  sarif: string;
}

/**
 * Redact, build, and write every local format. Shared by `session finish` and by
 * anything that changes a finished session afterwards (a retest that marks a
 * finding fixed), so the files on disk never disagree with the session.
 */
export async function writeLocalReport(
  state: SessionState,
  endedAt: Date,
  coverage: string[],
  limitations: string[],
  warnings: string[] = []
): Promise<{ report: ScanReport; files: LocalReportFiles; redactions: number }> {
  const knownSecrets = await loadKnownSecrets(state);
  const redacted = redactDeep(state.findings, knownSecrets);

  const baseline = await loadBaseline(state.repoRoot, warnings);
  const report: ScanReport = buildReport({
    id: state.localReportId,
    ...(state.cloud.reportId ? { cloudReportId: state.cloud.reportId } : {}),
    generatedAt: endedAt,
    project: {
      name: state.project.name,
      workspaceKind: state.project.workspaceKind,
      ...(state.project.workspaceName ? { workspaceName: state.project.workspaceName } : {}),
      repositoryLabel: path.basename(state.repoRoot)
    },
    scan: scanMetadata(state, endedAt),
    findings: redacted.value,
    coverage,
    coverageAreas: state.coverageAreas,
    limitations,
    candidateCount: state.candidateCount,
    duplicateCount: state.duplicateCount,
    ...(baseline ? { baseline } : {})
  });

  const directory = reportDirectory(state.repoRoot, state.localReportId);
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });

  const files: LocalReportFiles = {
    json: path.join(directory, "report.json"),
    html: path.join(directory, "report.html"),
    markdown: path.join(directory, "report.md"),
    sarif: path.join(directory, "report.sarif.json")
  };

  await fs.writeFile(files.json, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
  await fs.writeFile(
    files.html,
    renderStandaloneHtml(report, {
      contextLabel: state.cloud.state === "live" || state.cloud.state === "synced" ? "Local + synced" : "Local report",
      ...(state.cloud.reportUrl ? { cloudUrl: state.cloud.reportUrl } : {}),
      ...(state.cloud.expiresAt ? { expiresAt: state.cloud.expiresAt } : {})
    }),
    { mode: 0o600 }
  );
  await fs.writeFile(files.markdown, renderMarkdown(report), { mode: 0o600 });
  await fs.writeFile(files.sarif, renderSarif(report), { mode: 0o600 });
  return { report, files, redactions: redacted.replacements };
}

/**
 * Re-render a finished session's local report from its current state. A no-op
 * for a session that was never finished: it has no report to keep in step.
 */
export async function refreshLocalReport(state: SessionState): Promise<boolean> {
  if (!state.finishedAt) return false;
  await writeLocalReport(state, new Date(state.finishedAt), state.coverage, state.limitations);
  return true;
}

/**
 * Validate, redact, write every local format, then sync if this scan opted in.
 * A cloud failure never invalidates the local report.
 */
export async function finishSession(options: FinishOptions): Promise<SessionFinishResult> {
  const state = options.state;
  const endedAt = new Date();
  const warnings: string[] = [];

  markPhase(state, "reporting", "running", endedAt);
  const { coverage, limitations } = coverageDefaults(state);

  const { report, files, redactions } = await writeLocalReport(state, endedAt, coverage, limitations, warnings);
  if (redactions > 0) {
    warnings.push(`${redactions} secret-like value(s) were redacted during report generation.`);
  }

  markPhase(state, "reporting", "complete", endedAt);
  state.state = options.cancelled ? "cancelled" : "complete";
  state.finishedAt = endedAt.toISOString();
  state.findings = report.findings;
  state.coverage = coverage;
  state.limitations = limitations;
  await saveSession(state);

  const { client } = await resolveClient();
  let cloudError: string | undefined;

  if (state.cloud.state === "live" && client.authenticated) {
    await emitProgress(state, client, {
      type: "aggregate_updated",
      phase: "reporting",
      safeCode: "GENERATING_REPORT",
      aggregate: {
        candidateCount: state.candidateCount,
        validatedCount: report.summary.verificationCounts.verified,
        critical: report.summary.severityCounts.critical,
        high: report.summary.severityCounts.high,
        medium: report.summary.severityCounts.medium,
        low: report.summary.severityCounts.low,
        info: report.summary.severityCounts.info
      }
    });
    const outcome = await finalizeCloudReport(state, client, report);
    if (!outcome.synced) {
      cloudError = outcome.error;
      warnings.push(`${outcome.error} ${retryHint(state)}`);
    }
  }

  await track({
    name: options.cancelled ? "scan_cancelled" : "scan_completed",
    client: "cli",
    ...(state.cloud.reportId ? { reportId: state.cloud.reportId } : {}),
    ...(state.project.workspaceId ? { workspaceId: state.project.workspaceId } : {}),
    ...(state.project.projectId ? { projectId: state.project.projectId } : {}),
    agentName: state.agent.name,
    ...(state.agent.model ? { modelName: state.agent.model } : {}),
    effortRequested: state.effort.requested,
    effortResolved: state.effort.resolved,
    metrics: {
      duration_ms: report.scan.durationMs,
      candidate_count: state.candidateCount,
      duplicate_count: state.duplicateCount,
      validated_count: report.summary.verificationCounts.verified,
      severity_critical: report.summary.severityCounts.critical,
      severity_high: report.summary.severityCounts.high,
      severity_medium: report.summary.severityCounts.medium,
      severity_low: report.summary.severityCounts.low,
      severity_info: report.summary.severityCounts.info,
      verification_verified: report.summary.verificationCounts.verified,
      verification_strong_evidence: report.summary.verificationCounts.strong_evidence,
      verification_needs_review: report.summary.verificationCounts.needs_review,
      token_source: state.tokenUsage.source,
      ...(state.tokenUsage.count !== undefined ? { token_count: state.tokenUsage.count } : {}),
      external_authorized_target_count: state.scope.authorizedExternalTargets.length,
      isolated_runtime_available: state.host.isolatedRuntimeAvailable ?? false
    }
  });

  const result: SessionFinishResult = {
    localReportId: state.localReportId,
    files,
    summary: {
      findingCount: report.summary.findingCount,
      validatedCount: report.summary.verificationCounts.verified
    },
    cloud: {
      state: state.cloud.state === "decision_required" ? "not_requested" : state.cloud.state,
      ...(state.cloud.reportId ? { reportId: state.cloud.reportId } : {}),
      ...(state.cloud.reportUrl ? { reportUrl: state.cloud.reportUrl } : {}),
      ...(cloudError ? { error: cloudError } : {})
    },
    warnings
  };

  if (options.asJson) {
    json(result);
    return result;
  }

  heading("assessment complete");
  field("Project", state.project.name);
  if (report.verdict) field("Verdict", report.verdict.headline);
  field(
    "Findings",
    `${report.summary.findingCount} (${report.summary.verificationCounts.verified} verified, ${report.summary.verificationCounts.strong_evidence} strong evidence, ${report.summary.verificationCounts.needs_review} needs review)`
  );
  field(
    "Severity",
    `critical ${report.summary.severityCounts.critical} · high ${report.summary.severityCounts.high} · medium ${report.summary.severityCounts.medium} · low ${report.summary.severityCounts.low} · info ${report.summary.severityCounts.info}`
  );
  if (report.baseline) {
    field(
      "Baseline",
      `${report.baseline.counts.new} new · ${report.baseline.counts.unchanged} already known · ${report.baseline.counts.fixed} gone`
    );
  }
  blank();
  write(style.bold("Local report"));
  bullet(files.html);
  bullet(files.json);
  bullet(files.markdown);
  bullet(files.sarif);
  blank();
  if (result.cloud.reportUrl && result.cloud.state === "synced") {
    write(`${style.ok("Synced report")} ${result.cloud.reportUrl}`);
  } else if (state.cloud.state === "quota_blocked") {
    write(state.cloud.reason ?? "This report stayed local.");
  } else if (cloudError) {
    write(style.warn(`Cloud sync failed: ${cloudError}`));
    write(retryHint(state));
  }
  if (report.summary.findingCount === 0) {
    blank();
    write(
      "No findings were reported. That is not evidence that the application is secure; read the coverage and limitations in the report."
    );
  } else {
    blank();
    write(`Fix one on its own branch and retest it with "${BRAND.cliName} fix <finding-id>", or copy a prompt with "${BRAND.cliName} fix prompt <finding-id>".`);
  }
  blank();
  write(style.dim(stageTimings(snapshotFromSession(state, endedAt))));

  const host = detectHostAgent(process.env, state.agent.name);
  const unproven = report.findings.filter(
    (finding) => finding.verification !== "verified" && finding.status !== "false_positive" && finding.status !== "fixed_verified"
  ).length;
  if (!host.detected && report.summary.verificationCounts.verified === 0) {
    const hints = verificationHints(await installedAgentIds(state.repoRoot), state.effort.requested);
    blank();
    write(style.bold(staticOnlySummary(unproven, hints)));
  }
  for (const warning of warnings) write(style.warn(warning));
  return result;
}
