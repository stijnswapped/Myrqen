import fs from "node:fs/promises";
import path from "node:path";
import type { Severity } from "@myrqen/contracts";
import { reportDirectory } from "../config/paths.js";
import { listSessions, type SessionState } from "../session/state.js";
import { isOpen } from "./compare.js";

export type ReportFormat = "html" | "md" | "json" | "sarif";

export const REPORT_FILES: Readonly<Record<ReportFormat, string>> = Object.freeze({
  html: "report.html",
  md: "report.md",
  json: "report.json",
  sarif: "report.sarif.json"
});

export interface RunSummary {
  localReportId: string;
  createdAt: string;
  finishedAt?: string;
  state: string;
  effort: string;
  agent: string;
  findings: number;
  open: number;
  verified: number;
  fixed: number;
  refuted: number;
  severity: Record<Severity, number>;
  /** Whether `session finish` has written the local report files. */
  hasReport: boolean;
}

export function reportPath(state: Pick<SessionState, "repoRoot" | "localReportId">, format: ReportFormat): string {
  return path.join(reportDirectory(state.repoRoot, state.localReportId), REPORT_FILES[format]);
}

export async function hasReport(state: Pick<SessionState, "repoRoot" | "localReportId">): Promise<boolean> {
  try {
    await fs.access(reportPath(state, "json"));
    return true;
  } catch {
    return false;
  }
}

export async function summarizeRun(state: SessionState): Promise<RunSummary> {
  const standing = state.findings.filter((finding) => finding.status !== "false_positive");
  const severity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of standing.filter(isOpen)) severity[finding.severity] += 1;
  return {
    localReportId: state.localReportId,
    createdAt: state.createdAt,
    ...(state.finishedAt ? { finishedAt: state.finishedAt } : {}),
    state: state.state,
    effort: state.effort.resolved,
    agent: state.agent.name,
    findings: standing.length,
    open: standing.filter(isOpen).length,
    verified: standing.filter((finding) => finding.verification === "verified").length,
    fixed: standing.filter((finding) => finding.status === "fixed_verified").length,
    refuted: state.findings.length - standing.length,
    severity,
    hasReport: await hasReport(state)
  };
}

/** Sessions newest first. */
export async function listRuns(repoRoot: string): Promise<SessionState[]> {
  return listSessions(repoRoot);
}

/**
 * Resolve a run reference: a full local report id, a unique prefix of one
 * (with or without `rpt_`), or a 1-based position where 1 is the newest.
 */
export function resolveRun(runs: readonly SessionState[], reference: string): SessionState {
  const ref = reference.trim();
  if (/^\d{1,3}$/.test(ref)) {
    const run = runs[Number(ref) - 1];
    if (!run) throw new Error(`There are ${runs.length} run(s) here; "${ref}" is out of range.`);
    return run;
  }
  const exact = runs.find((run) => run.localReportId === ref);
  if (exact) return exact;
  const needle = ref.startsWith("rpt_") ? ref : `rpt_${ref}`;
  const matches = runs.filter((run) => run.localReportId.startsWith(needle));
  if (matches.length === 1) return matches[0]!;
  if (matches.length > 1) throw new Error(`"${ref}" matches ${matches.length} runs. Give more of the id.`);
  throw new Error(`No run "${ref}" in this repository. List them with "report --list".`);
}
