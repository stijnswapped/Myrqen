import { BRAND } from "@myrqen/brand";
import type { Finding } from "@myrqen/contracts";
import { formatDuration, formatTokenUsage, sortFindings, verificationLabel } from "./build.js";
import type { ViewableReport } from "./html.js";

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

/**
 * Snippets stay verbatim because fidelity matters in a security report, so the
 * fence has to be longer than the longest backtick run inside it; otherwise the
 * content closes the block early and the remainder is parsed as markup.
 */
function fence(content: string): string {
  const longestRun = Math.max(0, ...[...content.matchAll(/`+/g)].map((match) => match[0].length));
  const ticks = "`".repeat(Math.max(3, longestRun + 1));
  return `${ticks}\n${content}\n${ticks}`;
}

function findingSection(finding: Finding): string {
  const lines: string[] = [];
  lines.push(`### ${text(finding.id)} — ${text(finding.title)}`);
  lines.push("");
  lines.push(
    `- Severity: **${text(finding.severity)}**`,
    `- Verification: **${text(verificationLabel(finding.verification))}**`,
    `- Category: \`${text(finding.category)}\``,
    `- Affected: ${text(finding.affected.component)}${finding.affected.route ? ` · \`${text(finding.affected.route)}\`` : ""}${finding.affected.file ? ` · \`${text(finding.affected.file)}\`` : ""}`
  );
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

/** Portable human-readable report. Same projection rules as every other format. */
export function renderMarkdown(report: ViewableReport): string {
  const findings = sortFindings(report.findings ?? []);
  const lines: string[] = [];

  lines.push(`# ${BRAND.displayName} security assessment — ${text(report.project?.name ?? report.id)}`);
  lines.push("");
  if (report.generatedAt) lines.push(`Generated ${text(report.generatedAt)}`);
  if (report.redactionNotice) lines.push("", `> ${text(report.redactionNotice)}`);
  lines.push("");

  if (report.summary) {
    lines.push("## Summary", "");
    lines.push(
      `| Severity | Count |`,
      `| --- | --- |`,
      ...(["critical", "high", "medium", "low", "info"] as const).map(
        (severity) => `| ${severity} | ${report.summary?.severityCounts[severity] ?? 0} |`
      ),
      ""
    );
    lines.push(
      `Verified: ${report.summary.verificationCounts.verified} · Strong evidence: ${report.summary.verificationCounts.strong_evidence} · Needs review: ${report.summary.verificationCounts.needs_review}`,
      ""
    );
  }

  if (report.scan) {
    lines.push("## Scan metadata", "");
    lines.push(
      `- Effort: ${text(report.scan.effortRequested)} requested, ${text(report.scan.effortResolved)} resolved`,
      `- Host agent: ${text([report.scan.agent.name, report.scan.agent.version].filter(Boolean).join(" "))}`,
      `- Model: ${text(report.scan.agent.model ?? "unknown")}`,
      `- Duration: ${formatDuration(report.scan.durationMs)}`,
      `- Token usage: ${formatTokenUsage(report.scan.tokenUsage)}`,
      `- Local targets: ${text(report.scan.scope.localTargets.join(", ")) || "none recorded"}`,
      `- Authorized external targets: ${text(report.scan.scope.externalTargets.map((target) => target.target).join(", ")) || "none"}`,
      `- Destructive actions: not permitted`,
      ""
    );
  }

  lines.push("## Findings", "");
  if (findings.length === 0) {
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
