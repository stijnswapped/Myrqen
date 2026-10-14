import { BRAND } from "@myrqen/brand";
import type { Finding, ScanReport } from "@myrqen/contracts";

export interface FixPromptContext {
  projectName?: string;
  repositoryLabel?: string;
  cliName?: string;
  localReportId?: string;
  /** No agent drove the run: nothing was checked against the running app. */
  staticOnly?: boolean;
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
      ? `3. Record the outcome with "${cli} --session ${context.localReportId} fix record ${finding.id} --verified" only if verification actually passed.`
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

/** Findings a remediation pass should leave alone. */
const SETTLED_STATUS = new Set<string>(["fixed_verified", "false_positive", "accepted_risk"]);

const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/**
 * One prompt that remediates a whole report.
 *
 * `buildFixPrompt` handles one finding well and is the wrong shape for the job people
 * actually want, which is "fix what you found". Pasting fifteen separate prompts in
 * sequence re-states the constraints fifteen times, spends the agent's context on
 * repetition, and produces fifteen commits touching the same four files.
 *
 * Three things this says that a per-finding prompt structurally cannot:
 *
 * 1. **Order.** Findings are grouped by file and sorted by severity within it, so the
 *    agent opens each file once. A verified finding is placed before an unsettled one
 *    of the same severity, because one has been observed to reproduce and the other has
 *    not.
 * 2. **Rotation.** Deleting a committed key does not make it safe — it is in the git
 *    history and in every clone, and the only fix is to rotate it at the issuer. A
 *    remediation pass that quietly edits the literal out leaves the application exactly
 *    as compromised as it was, and looks finished. This is the single most common way a
 *    secret "fix" fails, so it is stated first and separately.
 * 3. **What not to trust.** A `needs_review` finding is a claim the scanner could not
 *    settle. Telling the agent to confirm before changing code is the difference between
 *    a remediation pass and fifteen speculative edits.
 *
 * Evidence snippets are deliberately omitted: they are the bulk of a per-finding prompt
 * and the agent is about to read the file anyway. The pointer to `fix prompt <id>` is
 * there for when one finding needs the full picture.
 */
export function buildFixAllPrompt(findings: readonly Finding[], context: FixPromptContext = {}): string {
  const cli = context.cliName ?? "myrqen";
  const open = findings.filter((finding) => !SETTLED_STATUS.has(finding.status ?? "open"));

  if (open.length === 0) {
    return `Nothing to fix: every ${BRAND.displayName} finding in this report is already verified fixed, accepted, or marked a false positive.`;
  }

  const rank = (finding: Finding): number =>
    (SEVERITY_RANK[finding.severity] ?? 9) * 10 +
    (finding.verification === "verified" ? 0 : finding.verification === "strong_evidence" ? 1 : 2);

  const byFile = new Map<string, Finding[]>();
  for (const finding of [...open].sort((a, b) => rank(a) - rank(b))) {
    const key = finding.affected.file ?? finding.affected.component;
    const bucket = byFile.get(key);
    if (bucket) bucket.push(finding);
    else byFile.set(key, [finding]);
  }

  const secrets = open.filter((finding) => finding.category === "hardcoded_secret");
  const unsettled = open.filter((finding) => finding.verification === "needs_review");
  const counts = ["critical", "high", "medium", "low", "info"]
    .map((severity) => ({ severity, n: open.filter((finding) => String(finding.severity) === severity).length }))
    .filter((entry) => entry.n > 0)
    .map((entry) => `${entry.n} ${entry.severity}`)
    .join(", ");

  const sections: string[] = [];
  for (const [file, group] of byFile) {
    const items = group.map((finding) => {
      const where = [
        finding.affected.lineStart ? `line ${finding.affected.lineStart}` : null,
        finding.affected.route ? `route ${finding.affected.route}` : null
      ]
        .filter(Boolean)
        .join(", ");
      return [
        `#### ${finding.id} — ${finding.title}`,
        `${finding.severity} · ${finding.verification.replaceAll("_", " ")} · ${finding.category}${where ? ` · ${where}` : ""}`,
        "",
        `Cause: ${finding.summary}`,
        `Fix: ${finding.remediation}`,
        `Confirm by: ${finding.verificationPlan}`
      ].join("\n");
    });
    sections.push([`### ${file}`, "", items.join("\n\n")].join("\n"));
  }

  const lines: (string | null)[] = [
    `Fix every open ${BRAND.displayName} finding in this report.`,
    "",
    context.projectName ? `Project: ${context.projectName}` : null,
    `Open findings: ${open.length} (${counts})`,
    context.localReportId ? `Report: ${context.localReportId}` : null,
    "",
    "## Read this before editing anything",
    "",
    secrets.length > 0
      ? `- **${secrets.length} committed credential${secrets.length === 1 ? "" : "s"}. Removing the literal is not the fix.** ` +
        "Each one is in the git history and in every clone and CI cache that ever pulled it. Rotate it at the issuer first, " +
        "move the new value to configuration the repository does not contain, and only then delete the literal. " +
        "A report that shows these as fixed because the line is gone is a report that is wrong."
      : null,
    unsettled.length > 0
      ? `- **${unsettled.length} finding${unsettled.length === 1 ? " is" : "s are"} marked "needs review".** ` +
        "The scanner could not settle those against a running application. Confirm each one is real before changing code, " +
        "and say so if it is not — a refuted finding is a useful result and deleting it silently is not."
      : null,
    "- Work file by file in the order below. Each file is listed once, most severe finding first.",
    "- Prefer the framework's own safeguard over a hand-rolled check.",
    "- Preserve unrelated behaviour and follow the conventions already in each file.",
    "- Never log, print, or hard-code a secret while fixing one.",
    "- Add the smallest useful regression test per finding: it must fail before the fix and pass after.",
    "- Do not refactor anything these findings do not require.",
    "",
    "## Findings",
    "",
    sections.join("\n\n"),
    "",
    "## When you are done, per finding",
    "",
    "1. Run the project's targeted tests for the affected area.",
    "2. Run that finding's own \"Confirm by\" step and check the issue no longer reproduces.",
    context.localReportId
      ? `3. Record it: \`${cli} --session ${context.localReportId} fix record <findingId> --verified\` — only if the confirmation actually passed.`
      : `3. Record it: \`${cli} fix record <findingId> --verified\` — only if the confirmation actually passed.`,
    "",
    `Marking a finding verified without running its confirmation step is the one thing not to do here. If a fix cannot be verified, record it with \`--applied\` and say why.`,
    "",
    `For the full evidence behind any single finding, run \`${cli} fix prompt <findingId>\`.`
  ];

  return lines.filter((line) => line !== null).join("\n");
}

export function buildFixAllPromptFromReport(report: ScanReport): string {
  const context: FixPromptContext = { projectName: report.project.name, localReportId: report.id };
  if (report.project.repositoryLabel) context.repositoryLabel = report.project.repositoryLabel;
  return buildFixAllPrompt(report.findings, context);
}

/** "src/server.js:119", or the origin or component when no file is recorded. */
export function findingLocation(finding: Pick<Finding, "affected">): string {
  const affected = finding.affected;
  if (affected.file) return `${affected.file}${affected.lineStart ? `:${affected.lineStart}` : ""}`;
  return affected.origin ?? affected.component;
}

/**
 * The short prompt the verdict hands out: what to change, where, and how to know it
 * worked, small enough to paste without scrolling.
 *
 * It carries the cautions `buildFixAllPrompt` leads with, one line each, because they
 * are how a quick fix most often goes wrong: deleting a committed key instead of
 * rotating it, editing on the strength of a claim nobody confirmed, and recording a
 * fix without running its check. The full evidence stays one command away.
 */
export function buildQuickFixPrompt(finding: Finding, context: FixPromptContext = {}): string {
  const cli = context.cliName ?? "myrqen";
  const where = [findingLocation(finding), finding.affected.route].filter(Boolean).join(" · ");
  const record = context.localReportId
    ? `${cli} --session ${context.localReportId} fix record ${finding.id} --verified`
    : `${cli} fix record ${finding.id} --verified`;
  const lines: Array<string | null> = [
    `Fix ${BRAND.displayName} finding ${finding.id}${context.projectName ? ` in ${context.projectName}` : ""}: ${finding.title}`,
    `${finding.severity} · ${finding.verification.replaceAll("_", " ")} · ${where}`,
    "",
    `Cause: ${finding.summary}`,
    `Fix: ${finding.remediation}`,
    `Confirm by: ${finding.verificationPlan}`,
    "",
    finding.verification === "needs_review" || (context.staticOnly && finding.verification !== "verified")
      ? "This finding is unconfirmed. Check that it is real before changing code; if it is not, say so and stop."
      : null,
    finding.category === "hardcoded_secret"
      ? "Rotate the credential at its issuer first. Deleting the literal does not remove it from git history."
      : null,
    "Keep the change scoped, prefer the framework's own safeguard, add a regression test that fails before the fix, and never print or hard-code a secret.",
    `When the confirmation passes, record it: ${record}`,
    `Full evidence: ${cli} fix prompt ${finding.id}`
  ];
  return lines.filter((line): line is string => line !== null).join("\n");
}
