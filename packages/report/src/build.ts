import { BRAND } from "@myrqen/brand";
import type {
  AuthorizationSummary,
  CoverageArea,
  Finding,
  ScanMetadata,
  ScanReport,
  WorkspaceKind
} from "@myrqen/contracts";
import { formatIssues, validateReport } from "@myrqen/contracts";
import { DEFAULT_PROHIBITED_ACTIONS } from "@myrqen/policy";

export const METHODOLOGY_VERSION = "1.0.0";

export interface BuildReportInput {
  id: string;
  cloudReportId?: string;
  generatedAt?: Date;
  project: { name: string; workspaceKind: WorkspaceKind; workspaceName?: string; repositoryLabel?: string };
  scan: ScanMetadata;
  findings: Finding[];
  coverage: string[];
  coverageAreas?: CoverageArea[];
  limitations: string[];
  candidateCount?: number;
  duplicateCount?: number;
}

function summarize(findings: Finding[]) {
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const verificationCounts = { verified: 0, strong_evidence: 0, needs_review: 0 };
  let fixedCount = 0;
  for (const finding of findings) {
    severityCounts[finding.severity] += 1;
    verificationCounts[finding.verification] += 1;
    if (finding.status === "fixed_verified") fixedCount += 1;
  }
  return { findingCount: findings.length, severityCounts, verificationCounts, fixedCount };
}

function authorizationSummary(scan: ScanMetadata): AuthorizationSummary {
  const notes: string[] = [];
  if (scan.scope.externalTargets.length > 0) {
    notes.push(
      `${scan.scope.externalTargets.length} external origin(s) were explicitly authorized for this scan at exact-origin granularity.`
    );
  } else {
    notes.push("No external origin was authorized. Only local project targets were assessed.");
  }
  if (scan.host?.isolatedRuntimeAvailable === false) {
    notes.push("Isolated runtime checks were skipped on this machine. Other checks still ran.");
  }
  return {
    destructiveActionsAllowed: false,
    prohibitedActions: DEFAULT_PROHIBITED_ACTIONS,
    externalTargetAuthorization: "exact_origin_only",
    localTargetsInScope: true,
    notes
  };
}

const NO_FINDING_LIMITATION =
  "No findings were reported. That is not evidence that the application is secure; see coverage for what was and was not assessed.";

/**
 * Assemble and validate the canonical report. Coverage honesty is enforced here:
 * a report always states what was not assessed.
 */
export function buildReport(input: BuildReportInput): ScanReport {
  const summary = summarize(input.findings);
  const limitations = [...input.limitations];
  if (input.findings.length === 0 && !limitations.some((line) => line.includes("not evidence"))) {
    limitations.push(NO_FINDING_LIMITATION);
  }
  if (limitations.length === 0) {
    limitations.push("No limitations were recorded for this scan.");
  }

  const report: ScanReport = {
    schemaVersion: BRAND.reportSchemaVersion as "1.0.0",
    id: input.id,
    generatedAt: (input.generatedAt ?? new Date()).toISOString(),
    project: input.project,
    scan: input.scan,
    authorization: authorizationSummary(input.scan),
    summary: {
      ...summary,
      ...(input.candidateCount !== undefined ? { candidateCount: input.candidateCount } : {}),
      ...(input.duplicateCount !== undefined ? { duplicateCount: input.duplicateCount } : {})
    },
    findings: input.findings,
    coverage: input.coverage.length > 0 ? input.coverage : ["No coverage notes were recorded."],
    limitations,
    methodologyVersion: METHODOLOGY_VERSION
  };
  if (input.cloudReportId) report.cloudReportId = input.cloudReportId;
  if (input.coverageAreas && input.coverageAreas.length > 0) report.coverageAreas = input.coverageAreas;

  const validation = validateReport(report);
  if (!validation.valid) {
    throw new Error(`Generated report failed schema validation:\n${formatIssues(validation.issues)}`);
  }
  return report;
}

export function formatDuration(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return "unknown";
  const totalSeconds = Math.round(ms / 1000);
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m ${seconds}s`;
  return `${seconds}s`;
}

export function formatTokenUsage(usage: ScanMetadata["tokenUsage"]): string {
  if (usage.source === "unavailable") return "Unavailable";
  const count = typeof usage.count === "number" ? usage.count.toLocaleString("en-US") : "unknown";
  if (usage.source === "exact") return `${count} (exact)`;
  return `~${count} (estimated${usage.estimator ? `, ${usage.estimator}` : ""})`;
}

export function severityLabel(severity: Finding["severity"]): string {
  return severity.toUpperCase();
}

export function verificationLabel(verification: Finding["verification"]): string {
  return verification === "strong_evidence"
    ? "Strong evidence"
    : verification === "needs_review"
      ? "Needs review"
      : "Verified";
}

/** Ordered for display: worst first, then verified before unverified. */
export function sortFindings(findings: Finding[]): Finding[] {
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
