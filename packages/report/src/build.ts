import { BRAND } from "@myrqen/brand";
import type {
  AuthorizationSummary,
  CoverageArea,
  Finding,
  ReportVerdictRecord,
  ScanMetadata,
  ScanReport,
  WorkspaceKind
} from "@myrqen/contracts";
import { formatIssues, validateReport } from "@myrqen/contracts";
import { DEFAULT_PROHIBITED_ACTIONS } from "@myrqen/policy";
import { compareToBaseline, type BaselineFile } from "./baseline.js";
import { complianceFor } from "./compliance.js";
import { countFindings } from "./facts.js";
import { buildVerdict, type ReportVerdict } from "./verdict.js";

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
  /** A parsed `.myrqen/baseline.json`, when the project has one. */
  baseline?: BaselineFile;
}

/** The stored summary, counted by the same function every renderer counts with. */
function summarize(findings: Finding[]): ScanReport["summary"] {
  const counts = countFindings(findings);
  return {
    findingCount: counts.total,
    severityCounts: counts.severity,
    verificationCounts: counts.verification,
    fixedCount: counts.fixed
  };
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

function verdictRecord(verdict: ReportVerdict): ReportVerdictRecord {
  const record: ReportVerdictRecord = {
    tone: verdict.tone,
    headline: verdict.headline,
    runMode: verdict.runMode,
    caveat: verdict.caveat,
    fixFirst: verdict.fixFirst.map((item) => ({ ...item }))
  };
  if (verdict.detail) record.detail = verdict.detail;
  if (verdict.nextStep) record.nextStep = verdict.nextStep;
  return record;
}

/**
 * Findings as the report stores them: each one carrying its standard references, and
 * its baseline state when a baseline was supplied. Both are derived, never asserted
 * by the agent, so they are rewritten here on every build.
 */
function annotateFindings(findings: Finding[], baseline: BaselineFile | undefined) {
  const comparison = baseline ? compareToBaseline(findings, baseline) : null;
  const annotated = findings.map((finding) => {
    const next: Finding = { ...finding, compliance: complianceFor(finding) };
    delete next.baselineState;
    const state = comparison?.states[finding.id];
    if (state) next.baselineState = state;
    return next;
  });
  return { annotated, comparison };
}

/**
 * Assemble and validate the canonical report. Coverage honesty is enforced here:
 * a report always states what was not assessed.
 */
export function buildReport(input: BuildReportInput): ScanReport {
  const { annotated, comparison } = annotateFindings(input.findings, input.baseline);
  const summary = summarize(annotated);
  const limitations = [...input.limitations];
  if (annotated.length === 0 && !limitations.some((line) => line.includes("not evidence"))) {
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
    findings: annotated,
    coverage: input.coverage.length > 0 ? input.coverage : ["No coverage notes were recorded."],
    limitations,
    methodologyVersion: METHODOLOGY_VERSION
  };
  if (input.cloudReportId) report.cloudReportId = input.cloudReportId;
  if (input.coverageAreas && input.coverageAreas.length > 0) report.coverageAreas = input.coverageAreas;
  if (comparison) {
    report.baseline = {
      createdAt: comparison.baselineCreatedAt,
      counts: { ...comparison.counts },
      fixed: comparison.fixed.map((entry) => ({ ...entry }))
    };
    if (comparison.fromReportId) report.baseline.fromReportId = comparison.fromReportId;
  }
  report.verdict = verdictRecord(buildVerdict(report));

  const validation = validateReport(report);
  if (!validation.valid) {
    throw new Error(`Generated report failed schema validation:\n${formatIssues(validation.issues)}`);
  }
  return report;
}

export function formatTokenUsage(usage: ScanMetadata["tokenUsage"]): string {
  if (usage.source === "unavailable") return "Unavailable";
  const count = typeof usage.count === "number" ? usage.count.toLocaleString("en-US") : "unknown";
  if (usage.source === "exact") return `${count} (exact)`;
  return `~${count} (estimated${usage.estimator ? `, ${usage.estimator}` : ""})`;
}
