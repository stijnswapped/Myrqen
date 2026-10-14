import type { Finding, FindingStatus, ReportSummary, ScanMetadata, Severity, Verification } from "@myrqen/contracts";
import type { ReportProjection, ScanReport } from "@myrqen/contracts";

/**
 * The one place a number in a report comes from.
 *
 * Every renderer used to count for itself: the overview prose counted the findings
 * it was handed, the stat cards read `summary`, the Markdown table read `summary`
 * again with its own defaults, and SARIF counted nothing at all. Any two of those
 * could disagree, and a security report whose headline number disagrees with its own
 * table is a report nobody should trust. Everything that prints a count now asks
 * this module, and the cross-format tests hold every format to it.
 */

export const SEVERITY_ORDER: readonly Severity[] = ["critical", "high", "medium", "low", "info"];
export const VERIFICATION_ORDER: readonly Verification[] = ["verified", "strong_evidence", "needs_review"];

/** Statuses that close a finding out. Everything else is still work. */
const SETTLED: ReadonlySet<FindingStatus> = new Set<FindingStatus>(["fixed_verified", "accepted_risk", "false_positive"]);

export interface FindingCounts {
  total: number;
  severity: Record<Severity, number>;
  verification: Record<Verification, number>;
  /** Fixed and verified. A fix that was applied but not verified is not counted. */
  fixed: number;
  /** Not fixed, not accepted, not refuted: what a reader still has to act on. */
  open: number;
  /** Open and verified: the findings that are both proven and still live. */
  openVerified: number;
}

export function isSettled(finding: Pick<Finding, "status">): boolean {
  return finding.status !== undefined && SETTLED.has(finding.status);
}

export function countFindings(findings: readonly Finding[]): FindingCounts {
  const severity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const verification: Record<Verification, number> = { verified: 0, strong_evidence: 0, needs_review: 0 };
  let fixed = 0;
  let open = 0;
  let openVerified = 0;
  for (const finding of findings) {
    severity[finding.severity] += 1;
    verification[finding.verification] += 1;
    if (finding.status === "fixed_verified") fixed += 1;
    if (!isSettled(finding)) {
      open += 1;
      if (finding.verification === "verified") openVerified += 1;
    }
  }
  return { total: findings.length, severity, verification, fixed, open, openVerified };
}

/** Counts carried by a summary alone, for a view that withholds the findings. */
function countsFromSummary(summary: ReportSummary): FindingCounts {
  const fixed = summary.fixedCount ?? 0;
  return {
    total: summary.findingCount,
    severity: { ...summary.severityCounts },
    verification: { ...summary.verificationCounts },
    fixed,
    // Without the findings, accepted and refuted ones cannot be told apart from open
    // ones. Only the verified fixes are known to be closed.
    open: Math.max(0, summary.findingCount - fixed),
    openVerified: summary.verificationCounts.verified
  };
}

export type RunMode = "agent" | "static_only" | "unattributed";

export interface RunAttribution {
  mode: RunMode;
  /** What to print where the host agent goes. Never the bare word "unknown". */
  agentLabel: string;
  modelLabel: string;
}

export const NO_AGENT_LABEL = "No agent — static pass only";
const NO_MODEL_LABEL = "None — no model reasoned about this run";
const NOT_RECORDED = "Not recorded";

function agentNamed(scan: Pick<ScanMetadata, "agent"> | undefined): boolean {
  const name = scan?.agent?.name?.trim().toLowerCase();
  return Boolean(name) && name !== "unknown" && name !== "none";
}

/**
 * Who drove the run. The CLI records the agent's name only when an agent passed it,
 * and the static pass tags every finding it produces, so a run with no named agent
 * whose every finding came from the static pass is a run no agent touched. Saying
 * "unknown" there undersells the most important caveat in the report: nothing in it
 * was looked at by anything that could have proven it.
 */
export function runAttribution(report: Pick<SummarizableFacts, "scan" | "findings">): RunAttribution {
  const scan = report.scan;
  if (agentNamed(scan)) {
    const agent = scan!.agent;
    return {
      mode: "agent",
      agentLabel: [agent.name, agent.version].filter(Boolean).join(" "),
      modelLabel: agent.model?.trim() ? agent.model : NOT_RECORDED
    };
  }
  const findings = report.findings;
  const staticOnly =
    Array.isArray(findings) &&
    findings.every((finding) => (finding.tags ?? []).includes("static-pass") && finding.verification !== "verified");
  if (staticOnly) return { mode: "static_only", agentLabel: NO_AGENT_LABEL, modelLabel: NO_MODEL_LABEL };
  return { mode: "unattributed", agentLabel: NOT_RECORDED, modelLabel: scan?.agent?.model?.trim() || NOT_RECORDED };
}

/** Minimal shape every renderer can describe: the canonical report or a projection. */
export type SummarizableFacts = Pick<ScanReport | ReportProjection, "findings" | "summary" | "scan" | "generatedAt">;

export interface ReportFacts {
  /** Where the counts were read from. `none` means this view carries neither. */
  source: "findings" | "summary" | "none";
  counts: FindingCounts | null;
  /**
   * Set only when the stored summary describes more findings than this view lists,
   * which happens when a projection withholds findings but keeps the summary.
   */
  recordedTotal?: number;
  candidateCount?: number;
  duplicateCount?: number;
  run: RunAttribution;
  durationLabel: string | null;
  generatedLabel: string | null;
}

/** "2026-10-13 12:39 UTC". One spelling for every format. */
export function formatTimestamp(iso: string | undefined): string | null {
  if (!iso) return null;
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return null;
  return `${date.toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

export function formatDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return "unknown";
  const totalSeconds = Math.round(ms / 1000);
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m ${seconds}s`;
  if (totalSeconds === 0 && ms > 0) return "under 1s";
  return `${seconds}s`;
}

export function severityLabel(severity: Severity): string {
  return severity.toUpperCase();
}

export function verificationLabel(verification: Verification): string {
  return verification === "strong_evidence"
    ? "Strong evidence"
    : verification === "needs_review"
      ? "Needs review"
      : "Verified";
}

/** Ordered for display: worst first, then verified before unverified. */
export function sortFindings(findings: readonly Finding[]): Finding[] {
  const severityRank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const verificationRank = { verified: 0, strong_evidence: 1, needs_review: 2 };
  return [...findings].sort((a, b) => {
    const bySeverity = severityRank[a.severity] - severityRank[b.severity];
    if (bySeverity !== 0) return bySeverity;
    const byVerification = verificationRank[a.verification] - verificationRank[b.verification];
    if (byVerification !== 0) return byVerification;
    return a.id.localeCompare(b.id);
  });
}

export function reportFacts(report: SummarizableFacts): ReportFacts {
  const findings = report.findings;
  const summary = report.summary;
  let source: ReportFacts["source"] = "none";
  let counts: FindingCounts | null = null;
  if (Array.isArray(findings)) {
    source = "findings";
    counts = countFindings(findings);
  } else if (summary) {
    source = "summary";
    counts = countsFromSummary(summary);
  }

  const facts: ReportFacts = {
    source,
    counts,
    run: runAttribution(report),
    durationLabel: report.scan ? formatDuration(report.scan.durationMs) : null,
    generatedLabel: formatTimestamp(report.generatedAt)
  };
  if (source === "findings" && summary && summary.findingCount > counts!.total) facts.recordedTotal = summary.findingCount;
  if (summary?.candidateCount !== undefined) facts.candidateCount = summary.candidateCount;
  if (summary?.duplicateCount !== undefined) facts.duplicateCount = summary.duplicateCount;
  return facts;
}
