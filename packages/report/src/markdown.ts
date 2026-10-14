import { BRAND } from "@myrqen/brand";
import type { Finding } from "@myrqen/contracts";
import { formatTokenUsage } from "./build.js";
import { aggregateCompliance, asvsLabel, complianceFor, complianceLine } from "./compliance.js";
import { SEVERITY_ORDER, reportFacts, sortFindings, verificationLabel, type ReportFacts } from "./facts.js";
import type { ViewableReport } from "./html.js";
import { buildVerdict, type ReportVerdict } from "./verdict.js";

/**
 * Findings carry adversary-authored strings by design. Markdown is a text format
 * so nothing executes inside Myrqen, but most renderers pass raw HTML through,
 * and a report piped into one of those turned a finding title into stored XSS in
 * that downstream context. Neutralizing the angle brackets means no tag can form
 * while the text still reads correctly once rendered.
 */
function text(value: unknown): string {
  return String(value ?? "").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}

/** Table cells additionally cannot contain a pipe or a line break. */
function cell(value: unknown): string {
  return text(value).replaceAll("|", "\\|").replace(/\s*\n\s*/g, " ");
}

/**
 * Snippets stay verbatim because fidelity matters in a security report, so the
 * fence has to be longer than the longest backtick run inside it; otherwise the
 * content closes the block early and the remainder is parsed as markup.
 */
function fence(content: string, info = ""): string {
  const longestRun = Math.max(0, ...[...content.matchAll(/`+/g)].map((match) => match[0].length));
  const ticks = "`".repeat(Math.max(3, longestRun + 1));
  return `${ticks}${info}\n${content}\n${ticks}`;
}

const BASELINE_LABEL = { new: "new", unchanged: "already in the baseline" } as const;

function findingSection(finding: Finding): string {
  const lines: string[] = [];
  lines.push(`### ${text(finding.id)} — ${text(finding.title)}`);
  lines.push("");
  lines.push(
    `- Severity: **${text(finding.severity)}**`,
    `- Verification: **${text(verificationLabel(finding.verification))}**`,
    `- Category: \`${text(finding.category)}\``,
    `- Standards: ${text(complianceLine(complianceFor(finding)))}`,
    `- Affected: ${text(finding.affected.component)}${finding.affected.route ? ` · \`${text(finding.affected.route)}\`` : ""}${finding.affected.file ? ` · \`${text(finding.affected.file)}${finding.affected.lineStart ? `:${finding.affected.lineStart}` : ""}\`` : ""}`
  );
  if (finding.baselineState) lines.push(`- Baseline: ${BASELINE_LABEL[finding.baselineState]}`);
  if (finding.status) lines.push(`- Status: ${text(finding.status.replaceAll("_", " "))}`);
  lines.push("", `**Root cause.** ${text(finding.summary)}`, "", `**Impact.** ${text(finding.impact)}`, "");

  const evidence = [...finding.evidence, ...(finding.corroboration ?? [])];
  if (evidence.length > 0) {
    lines.push("**Evidence.**", "");
    for (const item of evidence) {
      lines.push(`- _${text(item.kind.replaceAll("_", " "))}_ — ${text(item.description)}`);
      if (item.snippet) lines.push("", fence(item.snippet), "");
    }
    lines.push("");
  }
  if (finding.reproduction) lines.push("**Local reproduction.**", "", fence(finding.reproduction), "");
  lines.push(
    `**Remediation.** ${text(finding.remediation)}`,
    "",
    `**Verification.** ${text(finding.verificationPlan)}`,
    ""
  );
  return lines.join("\n");
}

function verdictSection(verdict: ReportVerdict): string[] {
  const lines = ["## Verdict", "", `**${text(verdict.headline)}**`, ""];
  if (verdict.detail) lines.push(text(verdict.detail), "");
  if (verdict.nextStep) lines.push(`Next: ${text(verdict.nextStep)}`, "");
  if (verdict.fixFirst.length > 0) {
    lines.push("### Fix these first", "");
    verdict.fixFirst.forEach((item, index) => {
      const where = [`\`${text(item.location)}\``, item.route ? `\`${text(item.route)}\`` : null].filter(Boolean).join(" · ");
      lines.push(
        `${index + 1}. **${text(item.findingId)} — ${text(item.title)}** — ${text(item.severity)} · ${text(verificationLabel(item.verification).toLowerCase())} · ${where}`,
        `   Why: ${text(item.why)}`,
        "",
        "   Prompt for your coding agent:",
        "",
        fence(item.fixPrompt, "text")
          .split("\n")
          .map((line) => `   ${line}`)
          .join("\n"),
        ""
      );
    });
  }
  lines.push(`> ${text(verdict.caveat)}`, "");
  return lines;
}

function summarySection(facts: ReportFacts): string[] {
  const counts = facts.counts;
  if (!counts) return [];
  const lines = ["## Summary", ""];
  lines.push(
    `Findings: ${counts.total} (${counts.open} open, ${counts.fixed} fixed and verified)${
      facts.recordedTotal !== undefined ? ` — this view lists ${counts.total} of the ${facts.recordedTotal} recorded` : ""
    }`,
    ""
  );
  lines.push(`| Severity | Count |`, `| --- | --- |`, ...SEVERITY_ORDER.map((severity) => `| ${severity} | ${counts.severity[severity]} |`), "");
  lines.push(
    `Verified: ${counts.verification.verified} · Strong evidence: ${counts.verification.strong_evidence} · Needs review: ${counts.verification.needs_review}`,
    ""
  );
  return lines;
}

function complianceSection(findings: Finding[]): string[] {
  if (findings.length === 0) return [];
  const rows = aggregateCompliance(findings);
  return [
    "## Compliance",
    "",
    "Findings grouped by OWASP Top 10:2025, with the CWE and OWASP ASVS references behind them. A finding that maps to two categories is listed under both.",
    "",
    "| OWASP Top 10:2025 | Findings | CWE | ASVS |",
    "| --- | --- | --- | --- |",
    ...rows.map(
      (row) =>
        `| ${cell(row.id === "unmapped" ? row.title : `${row.id} ${row.title}`)} | ${cell(row.findingIds.join(", "))} | ${cell(row.cwe.join(", ") || "—")} | ${cell(row.asvs.map(asvsLabel).join(", ") || "—")} |`
    ),
    ""
  ];
}

function baselineSection(report: ViewableReport): string[] {
  const baseline = report.baseline;
  if (!baseline) return [];
  const lines = [
    "## Baseline",
    "",
    `Compared with the baseline taken ${text(baseline.createdAt.slice(0, 10))}${baseline.fromReportId ? ` from ${text(baseline.fromReportId)}` : ""}: ${baseline.counts.new} new · ${baseline.counts.unchanged} already in the baseline · ${baseline.counts.fixed} fixed since.`,
    ""
  ];
  if (baseline.fixed.length > 0) {
    lines.push("Gone since the baseline (no longer reported by this scan):", "");
    for (const entry of baseline.fixed) {
      lines.push(`- ${text(entry.severity)} · \`${text(entry.category)}\` — ${text(entry.title)}${entry.file ? ` · \`${text(entry.file)}\`` : ""}${entry.route ? ` · \`${text(entry.route)}\`` : ""}`);
    }
    lines.push("");
  }
  return lines;
}

/** Portable human-readable report. Same projection rules as every other format. */
export function renderMarkdown(report: ViewableReport): string {
  const findings = sortFindings(report.findings ?? []);
  const facts = reportFacts(report);
  const verdict = buildVerdict(report);
  const lines: string[] = [];

  lines.push(`# ${BRAND.displayName} security assessment — ${text(report.project?.name ?? report.id)}`);
  lines.push("");
  const meta = [
    facts.generatedLabel ? `Generated ${facts.generatedLabel}` : null,
    report.scan ? `${text(report.scan.effortResolved)} effort` : null,
    report.scan ? text(facts.run.agentLabel) : null,
    facts.durationLabel
  ].filter(Boolean);
  if (meta.length > 0) lines.push(meta.join(" · "));
  if (report.redactionNotice) lines.push("", `> ${text(report.redactionNotice)}`);
  lines.push("");

  lines.push(...verdictSection(verdict));
  lines.push(...summarySection(facts));
  lines.push(...baselineSection(report));
  lines.push(...complianceSection(findings));

  if (report.scan) {
    lines.push("## Scan metadata", "");
    lines.push(
      `- Effort: ${text(report.scan.effortRequested)} requested, ${text(report.scan.effortResolved)} resolved`,
      `- Host agent: ${text(facts.run.agentLabel)}`,
      `- Model: ${text(facts.run.modelLabel)}`,
      `- Duration: ${facts.durationLabel}`,
      `- Token usage: ${formatTokenUsage(report.scan.tokenUsage)}`,
      ...(facts.candidateCount !== undefined ? [`- Candidates assessed: ${facts.candidateCount}`] : []),
      ...(facts.duplicateCount !== undefined ? [`- Duplicates merged: ${facts.duplicateCount}`] : []),
      `- Local targets: ${text(report.scan.scope.localTargets.join(", ")) || "none recorded"}`,
      `- Authorized external targets: ${text(report.scan.scope.externalTargets.map((target) => target.target).join(", ")) || "none"}`,
      `- Destructive actions: not permitted`,
      ""
    );
  }

  lines.push("## Findings", "");
  if (!Array.isArray(report.findings)) {
    lines.push("This view does not include the report's findings.", "");
  } else if (findings.length === 0) {
    lines.push(
      "No findings were reported. That is not evidence that the application is secure; read the coverage and limitations below.",
      ""
    );
  } else {
    for (const finding of findings) lines.push(findingSection(finding));
  }

  if (report.coverage?.length) {
    lines.push("## Coverage", "", ...report.coverage.map((line) => `- ${text(line)}`), "");
  }
  if (report.coverageAreas?.length) {
    lines.push(
      "## Coverage by area",
      "",
      ...report.coverageAreas.map(
        (area) =>
          `- ${area.assessed ? "assessed" : "not assessed"} — ${text(area.area)}${area.note ? ` (${text(area.note)})` : ""}`
      ),
      ""
    );
  }
  if (report.limitations?.length) {
    lines.push("## Limitations", "", ...report.limitations.map((line) => `- ${text(line)}`), "");
  }

  lines.push("---", "", BRAND.reportFooter, "");
  return lines.join("\n");
}
