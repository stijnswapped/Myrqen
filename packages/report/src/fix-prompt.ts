import { BRAND } from "@myrqen/brand";
import type { Finding, ScanReport } from "@myrqen/contracts";

export interface FixPromptContext {
  projectName?: string;
  repositoryLabel?: string;
  cliName?: string;
  localReportId?: string;
}

/**
 * The prompt must give a coding agent enough project-local context to remediate
 * and retest, and must never carry a raw secret. Findings are redacted at intake,
 * so this only assembles already-safe fields.
 */
export function buildFixPrompt(finding: Finding, context: FixPromptContext = {}): string {
  const cli = context.cliName ?? "myrqen";
  const location = [
    finding.affected.file
      ? `file: ${finding.affected.file}${finding.affected.lineStart ? `:${finding.affected.lineStart}` : ""}`
      : null,
    finding.affected.route ? `route: ${finding.affected.route}` : null,
    finding.affected.origin ? `origin: ${finding.affected.origin}` : null,
    `component: ${finding.affected.component}`
  ]
    .filter(Boolean)
    .join("\n");

  const evidence = [...finding.evidence, ...(finding.corroboration ?? [])]
    .map((item, index) => {
      const head = `${index + 1}. [${item.kind}] ${item.description}`;
      return item.snippet ? `${head}\n\`\`\`\n${item.snippet}\n\`\`\`` : head;
    })
    .join("\n");

  const lines = [
    `Fix ${BRAND.displayName} finding ${finding.id}: ${finding.title}`,
    "",
    context.projectName ? `Project: ${context.projectName}` : null,
    `Severity: ${finding.severity}`,
    `Verification: ${finding.verification.replaceAll("_", " ")}`,
    `Category: ${finding.category}`,
    "",
    "## Where",
    location,
    "",
    "## Root cause",
    finding.summary,
    "",
    "## Impact",
    finding.impact,
    "",
    "## Evidence",
    evidence || "No structured evidence was recorded.",
    finding.reproduction ? "\n## Local reproduction\n" + finding.reproduction : null,
    "",
    "## Required remediation",
    finding.remediation,
    "",
    "## Verification",
    finding.verificationPlan,
    "",
    "## Constraints",
    "- Preserve unrelated behavior and follow existing project conventions.",
    "- Prefer the framework's own safeguard over a hand-rolled check.",
    "- Do not log, print, or hard-code any secret while fixing this.",
    "- Add or update the smallest useful regression test that would fail before the fix.",
    "- Keep the change scoped to this finding; do not refactor unrelated code.",
    "",
    "## After the change",
    `1. Run the project's targeted tests for the affected area.`,
    `2. Re-run the ${BRAND.displayName} verification above and confirm it now fails to reproduce the issue.`,
    context.localReportId
      ? `3. Record the outcome with "${cli} fix record ${finding.id} --report ${context.localReportId} --verified" only if verification actually passed.`
      : `3. Record the outcome with "${cli} fix record ${finding.id} --verified" only if verification actually passed.`,
    "",
    "Do not mark this finding fixed unless the targeted security verification passes."
  ];

  return lines.filter((line) => line !== null).join("\n");
}

export function buildFixPromptFromReport(report: ScanReport, findingId: string): string | null {
  const finding = report.findings.find((item) => item.id === findingId);
  if (!finding) return null;
  const context: FixPromptContext = { projectName: report.project.name, localReportId: report.id };
  if (report.project.repositoryLabel) context.repositoryLabel = report.project.repositoryLabel;
  return buildFixPrompt(finding, context);
}
