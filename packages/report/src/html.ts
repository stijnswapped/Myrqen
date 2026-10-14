import { BRAND } from "@myrqen/brand";
import type {
  Finding,
  FindingEvidence,
  ReportBaselineRecord,
  ReportProjection,
  ScanReport,
  Severity,
  Verification
} from "@myrqen/contracts";
import { buildFixPrompt } from "./fix-prompt.js";
import { formatTokenUsage } from "./build.js";
import { aggregateCompliance, asvsLabel, complianceFor, cweUrl } from "./compliance.js";
import {
  SEVERITY_ORDER,
  formatDuration,
  VERIFICATION_ORDER,
  reportFacts,
  sortFindings,
  verificationLabel,
  type ReportFacts
} from "./facts.js";
import { CODE_STYLES, renderCode } from "./highlight.js";
import { REPORT_SCRIPT } from "./html-script.js";
import { REPORT_STYLES } from "./html-styles.js";
import { attackPath, executiveSummary } from "./summary.js";
import { buildVerdict, type ReportVerdict } from "./verdict.js";

/**
 * The renderer accepts either the canonical report or a server-generated viewer
 * projection. Anything absent from the input is absent from the output: the HTML
 * never receives hidden content to filter client-side.
 */
export type ViewableReport = (ScanReport | ReportProjection) & {
  /** Present on projections that withhold content from the current viewer. */
  redactionNotice?: string;
  /** Present on canonical reports compared against a committed baseline. */
  baseline?: ReportBaselineRecord;
};

export interface RenderOptions {
  /** Shown in the header, for example "Local report" or a viewer label. */
  contextLabel?: string;
  /** Adds a non-alarming banner, used for shared/anonymized views. */
  notice?: string;
  /** Print-oriented layout for PDF export paths. */
  print?: boolean;
  cloudUrl?: string;
  expiresAt?: string;
}

function esc(value: unknown): string {
  return String(value ?? "").replace(
    /[&<>"']/g,
    (character) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character] ?? character
  );
}

function jsonForScript(value: unknown): string {
  // Escape sequences that would otherwise terminate the script element or break
  // JSON parsing inside HTML.
  return JSON.stringify(value)
    .replace(/</g, "\\u003c")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

function humanize(value: string): string {
  return value.replaceAll("_", " ").trim();
}

function allEvidence(finding: Finding): FindingEvidence[] {
  return [...finding.evidence, ...(finding.corroboration ?? [])];
}

const SEVERITY_GLYPH: Record<Severity, string> = {
  critical: "◆◆◆",
  high: "◆◆",
  medium: "◆",
  low: "◇",
  info: "·"
};

const VERIFICATION_GLYPH: Record<Verification, string> = {
  verified: "✓",
  strong_evidence: "≈",
  needs_review: "?"
};

/**
 * What each verification state actually means, in the words the methodology uses.
 * This is the single most important honesty in the report: three findings printed
 * with the same weight read as three equally certain facts, and only one of these
 * three states is a fact. The sentence is printed next to every finding rather than
 * hidden in a legend, because a reader who scrolled straight to a finding never saw
 * the legend.
 */
const VERIFICATION_MEANING: Record<Verification, string> = {
  verified:
    "Deterministic local or authorized evidence demonstrated this. The proof below is what was observed, not what was expected.",
  strong_evidence:
    "The root cause and a reachable path are strongly supported by the evidence below, but full proof was unavailable or unsafe to obtain.",
  needs_review:
    "Plausible and unsettled. Nothing exercised this against the running application, so read the evidence and decide for yourself."
};

const STATUS_LABEL: Record<NonNullable<Finding["status"]>, string> = {
  open: "Open",
  fix_suggested: "Fix suggested",
  fix_applied: "Fix applied, not verified",
  fixed_verified: "Fixed and verified",
  accepted_risk: "Accepted risk",
  false_positive: "Marked false positive"
};

/** Only a verified fix counts as fixed. Everything else is still open work. */
function findingState(finding: Finding): "open" | "fixed" {
  return finding.status === "fixed_verified" ? "fixed" : "open";
}

function lineSuffix(finding: Finding): string {
  const start = finding.affected.lineStart;
  if (!start) return "";
  const end = finding.affected.lineEnd;
  return end && end !== start ? `:${start}-${end}` : `:${start}`;
}

/** Route, file, and origin, in the order a developer would go looking. */
function whereLine(finding: Finding): string {
  const file = finding.affected.file ? `${finding.affected.file}${lineSuffix(finding)}` : "";
  const parts = [finding.affected.route, file, finding.affected.origin].filter(Boolean) as string[];
  return parts.length > 0 ? parts.join("  ·  ") : finding.affected.component;
}

/** The text the search box matches against. Prose is deliberately left out: a search
 * that matches every finding on the word "request" is a search that helps nobody. */
function searchKey(finding: Finding): string {
  return [
    finding.id,
    finding.title,
    humanize(finding.category),
    finding.affected.component,
    finding.affected.route ?? "",
    finding.affected.file ?? "",
    finding.affected.origin ?? "",
    ...(finding.taxonomy ?? []),
    ...(finding.tags ?? [])
  ]
    .join(" ")
    .toLowerCase();
}

/**
 * The findings that carry both weight and evidence. Severity alone would promote an
 * unreviewed guess to the top of the page, and verification alone would promote a
 * proven cosmetic issue; a reader who acts on the first section should be acting on
 * something that is both serious and supported.
 */
function isPriority(finding: Finding): boolean {
  const severe = finding.severity === "critical" || finding.severity === "high";
  const supported = finding.verification === "verified" || finding.verification === "strong_evidence";
  return severe && supported && findingState(finding) === "open";
}

interface Buckets {
  priority: Finding[];
  verified: Finding[];
  other: Finding[];
}

/**
 * Three disjoint groups, so no finding is counted twice and every heading is true of
 * everything under it. "Verified findings" holds what is proven but less severe;
 * "Other findings" holds everything still carrying a caveat, including work already
 * closed out, which is why a fixed critical does not sit in the priority section.
 */
function bucketFindings(findings: Finding[]): Buckets {
  const priority: Finding[] = [];
  const verified: Finding[] = [];
  const other: Finding[] = [];
  for (const finding of findings) {
    if (isPriority(finding)) priority.push(finding);
    else if (finding.verification === "verified" && findingState(finding) === "open") verified.push(finding);
    else other.push(finding);
  }
  return { priority, verified, other };
}

/**
 * Where the excerpt starts in the file.
 *
 * A report records the line a finding is on, never the first line of the excerpt
 * quoted beside it, and the excerpt is cut with the same number of context lines
 * above and below the reported range. That symmetry is what makes the first line
 * recoverable: halve whatever the excerpt has beyond the reported range. When the
 * difference is odd or negative the excerpt is not centred on the range — it was
 * clipped at the start or end of the file, or the snippet is not this finding's own
 * code — and no start line is claimed at all, because a gutter that is off by two
 * sends a developer to the wrong line with the report's authority behind it.
 */
function excerptStartLine(finding: Finding, snippet: string): number | null {
  const start = finding.affected.lineStart;
  if (typeof start !== "number" || !Number.isFinite(start) || start < 1) return null;
  const declaredEnd = finding.affected.lineEnd;
  const end = typeof declaredEnd === "number" && declaredEnd >= start ? declaredEnd : start;
  const excerptLines = snippet.replace(/\n+$/, "").split("\n").length;
  const context = excerptLines - (end - start + 1);
  if (context < 0 || context % 2 !== 0) return null;
  const first = start - context / 2;
  return first >= 1 ? first : null;
}

/** The evidence whose snippet is the finding's own code, preferred over any other. */
function codeEvidence(finding: Finding): FindingEvidence | null {
  const withSnippet = allEvidence(finding).filter((item) => item.snippet && item.snippet.trim() !== "");
  if (withSnippet.length === 0) return null;
  const file = finding.affected.file;
  if (file) {
    const own = withSnippet.find((item) => (item.location ?? "").startsWith(file));
    if (own) return own;
  }
  return withSnippet[0] ?? null;
}

/* ------------------------------------------------------------------ *
 * Presentation
 * ------------------------------------------------------------------ */


/* ------------------------------------------------------------------ *
 * Finding
 * ------------------------------------------------------------------ */

function severityChip(severity: Severity): string {
  return `<span class="sev" data-sev="${esc(severity)}"><span aria-hidden="true">${SEVERITY_GLYPH[severity]}</span>${esc(severity)}</span>`;
}

function verificationChip(verification: Verification): string {
  return `<span class="ver" data-ver="${esc(verification)}"><span aria-hidden="true">${VERIFICATION_GLYPH[verification]}</span>${esc(verificationLabel(verification))}</span>`;
}

const BASELINE_CHIP: Record<NonNullable<Finding["baselineState"]>, string> = {
  new: "New since baseline",
  unchanged: "In baseline"
};

function marksBlock(finding: Finding): string {
  const status = finding.status && finding.status !== "open" ? STATUS_LABEL[finding.status] : "";
  return `<div class="marks">
      ${severityChip(finding.severity)}
      ${verificationChip(finding.verification)}
      ${status ? `<span class="status">${esc(status)}</span>` : ""}
      ${finding.baselineState ? `<span class="base" data-baseline="${esc(finding.baselineState)}">${esc(BASELINE_CHIP[finding.baselineState])}</span>` : ""}
      <span class="cat">${esc(humanize(finding.category))}</span>
    </div>`;
}

/** CWE, OWASP Top 10 (both editions), and ASVS, as the compliance table maps them. */
function standardsBlock(finding: Finding): string {
  const reference = complianceFor(finding);
  const items: string[] = [
    ...reference.cwe.map((cwe) => {
      const url = cweUrl(cwe);
      return `<li>${url ? `<a href="${esc(url)}" rel="noreferrer noopener" target="_blank"><b>${esc(cwe)}</b></a>` : `<b>${esc(cwe)}</b>`}</li>`;
    }),
    ...reference.owasp2025.map((id) => `<li>OWASP <b>${esc(id)}</b></li>`),
    ...reference.owasp2021.map((id) => `<li>OWASP <b>${esc(id)}</b></li>`),
    ...reference.asvs.map((id) => `<li>${esc(asvsLabel(id))}</li>`)
  ];
  if (items.length === 0) return "";
  return `<h4>Standards</h4><ul class="refs" aria-label="Standard references">${items.join("")}</ul>`;
}

function proofBlock(finding: Finding, promoted: FindingEvidence | null): string {
  const evidence = allEvidence(finding);
  if (evidence.length === 0) return `<p class="calm">No evidence detail is available in this view.</p>`;
  return `<ul class="evidence">${evidence
    .map((item) => {
      // The promoted snippet is rendered once, under "Affected code". Printing it
      // twice would read as two independent observations of the same line.
      const snippet = item !== promoted && item.snippet ? item.snippet : "";
      return `<li>
      <span class="ekind">${esc(humanize(item.kind))}</span>
      <p>${esc(item.description)}</p>
      ${item.location ? `<div class="eloc">${esc(item.location)}</div>` : ""}
      ${snippet ? `<pre class="plain"><code>${esc(snippet)}</code></pre>` : ""}
      ${item.redacted && !snippet ? `<div class="redacted">Some detail in this evidence is not shown in this view.</div>` : ""}
    </li>`;
    })
    .join("")}</ul>`;
}

function attackPathBlock(finding: Finding): string {
  const steps = attackPath(finding);
  // Most findings have no data flow to draw — a hard-coded credential and a missing
  // ownership check are real without one — and an invented path would be the report
  // asserting something its evidence never said. Those get no section at all.
  if (!steps || steps.length === 0) return "";
  return `<h4>Attack path</h4>
    <ol class="path">${steps
      .map(
        (step) =>
          `<li><span class="step">${esc(step.label)}</span>${step.detail ? `<span class="detail">${esc(step.detail)}</span>` : ""}</li>`
      )
      .join("")}</ol>`;
}

function affectedCodeBlock(finding: Finding, promoted: FindingEvidence | null): string {
  const snippet = promoted?.snippet;
  if (!snippet) return "";
  const filePath = finding.affected.file ?? promoted?.location ?? "";
  const startLine = excerptStartLine(finding, snippet);
  const lineStart = finding.affected.lineStart;
  const lineEnd = finding.affected.lineEnd;
  const range: [number, number] | null =
    startLine !== null && typeof lineStart === "number"
      ? [lineStart, typeof lineEnd === "number" && lineEnd >= lineStart ? lineEnd : lineStart]
      : null;

  const block = renderCode(snippet, {
    ...(startLine !== null ? { startLine } : {}),
    ...(range ? { highlight: range } : {}),
    ...(filePath ? { filePath } : {})
  });
  if (block === "") return "";

  return `<h4>Affected code</h4>
    <div class="codewrap">${block}</div>
    ${
      startLine === null
        ? `<p class="blocknote">Lines are numbered from the start of this excerpt. The report records ${esc(
            finding.affected.file ? `${finding.affected.file}${lineSuffix(finding)}` : "no file position"
          )}, but not where the excerpt itself begins in the file.</p>`
        : ""
    }
    <div class="codebar">
      <button class="copy secondary tiny" type="button" data-copy-text="${esc(snippet)}">Copy this excerpt</button>
    </div>`;
}

function fixHistoryBlock(finding: Finding): string {
  if (!finding.fixHistory || finding.fixHistory.length === 0) return "";
  return `<ul class="list">${finding.fixHistory
    .map(
      (entry) =>
        `<li><b>${esc(humanize(entry.action))}</b> — ${esc(entry.at)}${entry.verified ? " · verification passed" : " · not verified"}${entry.note ? ` · ${esc(entry.note)}` : ""}</li>`
    )
    .join("")}</ul>`;
}

function classificationLine(finding: Finding): string {
  const parts = [
    `Category ${humanize(finding.category)}`,
    finding.taxonomy && finding.taxonomy.length > 0 ? finding.taxonomy.join(", ") : "",
    finding.fingerprint ? `fingerprint ${finding.fingerprint}` : "",
    finding.firstSeenAt ? `first seen ${finding.firstSeenAt}` : ""
  ].filter(Boolean) as string[];
  return `<p class="blocknote">${esc(parts.join("  ·  "))}</p>`;
}

interface FindingOptions {
  rank: "lead" | "standard";
  open: boolean;
  promptAvailable: boolean;
}

function findingBlock(finding: Finding, options: FindingOptions): string {
  const promoted = codeEvidence(finding);
  const state = findingState(finding);
  return `<article class="finding" id="${esc(finding.id)}" data-sev="${esc(finding.severity)}" data-ver="${esc(finding.verification)}" data-state="${state}" data-component="${esc(finding.affected.component)}" data-rank="${options.rank}" data-search="${esc(searchKey(finding))}">
  <details class="disclosure"${options.open ? " open" : ""}>
    <summary class="fhead">
      ${marksBlock(finding)}
      <div class="ftitle">
        <h3><span class="fid">${esc(finding.id)}</span> ${esc(finding.title)}</h3>
        <div class="where">${esc(whereLine(finding))}</div>
        <p class="lede-impact">${esc(finding.impact)}</p>
      </div>
      <span class="chev" aria-hidden="true"><span class="more">Read the evidence</span><span class="less">Collapse</span></span>
    </summary>
    <div class="fbody">
      <div class="vmean" data-ver="${esc(finding.verification)}">
        <b>${esc(verificationLabel(finding.verification))}</b>
        <p>${esc(VERIFICATION_MEANING[finding.verification])}</p>
      </div>
      <h4>What ${esc(BRAND.displayName)} found</h4>
      <p>${esc(finding.summary)}</p>
      <h4>Why this matters</h4>
      <p>${esc(finding.impact)}</p>
      <h4>Proof</h4>
      ${proofBlock(finding, promoted)}
      ${attackPathBlock(finding)}
      ${affectedCodeBlock(finding, promoted)}
      ${finding.reproduction ? `<h4>Reproduction</h4><pre class="plain"><code>${esc(finding.reproduction)}</code></pre>` : ""}
      <h4>Recommended fix</h4>
      <p>${esc(finding.remediation)}</p>
      ${fixHistoryBlock(finding)}
      <h4>Verification</h4>
      <p>${esc(finding.verificationPlan)}</p>
      ${standardsBlock(finding)}
      ${classificationLine(finding)}
      <div class="actions">
        ${options.promptAvailable ? `<button class="copy" type="button" data-prompt-for="${esc(finding.id)}">Copy prompt to fix</button>` : ""}
        <button class="copy secondary" type="button" data-copy-text="${esc(`${finding.id} ${finding.title}`)}">Copy finding reference</button>
        <span class="hint">Applying a change is always an explicit action in your coding agent.</span>
      </div>
    </div>
  </details>
</article>`;
}

/* ------------------------------------------------------------------ *
 * Sections
 * ------------------------------------------------------------------ */

interface BarEntry {
  attribute: string;
  label: string;
  count: number;
}

/** Width is a proportion of counts the report already carries, and no percentage is
 * printed: the numbers beside the bar are the claim, the bar is only its shape. */
function barBlock(title: string, entries: BarEntry[], total: number, describe: string): string {
  const present = entries.filter((entry) => entry.count > 0);
  const bar =
    total > 0 && present.length > 0
      ? `<div class="bar" role="img" aria-label="${esc(describe)}">${present
          .map(
            (entry) =>
              `<span class="seg" ${entry.attribute} style="width:${((entry.count / total) * 100).toFixed(4)}%"></span>`
          )
          .join("")}</div>`
      : `<div class="bar" role="presentation"></div>`;
  return `<div class="card">
    <h3>${esc(title)}</h3>
    ${bar}
    <ul class="barkey">${entries
      .map(
        (entry) =>
          `<li ${entry.attribute}><span class="dot" ${entry.attribute} aria-hidden="true"></span>${esc(entry.label)} <b>${entry.count}</b></li>`
      )
      .join("")}</ul>
  </div>`;
}

/**
 * Every figure here comes from `reportFacts`, the same counts the verdict, the
 * prose, the Markdown, and the SARIF are built from. They are printed as they are:
 * no count-up animation, because a figure caught mid-animation by a screenshot or a
 * print is a smaller number of findings than the report contains.
 */
function statsBlock(facts: ReportFacts): string {
  const counts = facts.counts;
  if (!counts) return "";

  const severityDescription = `${counts.total} findings: ${SEVERITY_ORDER.map(
    (severity) => `${counts.severity[severity]} ${severity}`
  ).join(", ")}`;
  const verificationDescription = VERIFICATION_ORDER.map(
    (verification) => `${counts.verification[verification]} ${verificationLabel(verification).toLowerCase()}`
  ).join(", ");

  const verifiedTone = counts.verification.verified > 0 ? "verified" : "zero-verified";
  const numbers: Array<[string, string, number, string?]> = [
    ["findings", "Findings", counts.total],
    ["verified", "Verified", counts.verification.verified, verifiedTone],
    ["fixed", "Fixed and verified", counts.fixed]
  ];
  if (facts.candidateCount !== undefined) numbers.push(["candidates", "Candidates assessed", facts.candidateCount]);
  if (facts.duplicateCount !== undefined) numbers.push(["duplicates", "Duplicates merged", facts.duplicateCount]);

  const mismatch =
    facts.recordedTotal !== undefined
      ? `<p class="mismatch">This view lists ${counts.total} of the ${facts.recordedTotal} findings recorded in the report.</p>`
      : "";

  return `<div class="stats">
    ${barBlock(
      "By severity",
      SEVERITY_ORDER.map((severity) => ({
        attribute: `data-sev="${severity}"`,
        label: severity,
        count: counts.severity[severity]
      })),
      counts.total,
      severityDescription
    )}
    ${barBlock(
      "By verification",
      VERIFICATION_ORDER.map((verification) => ({
        attribute: `data-ver="${verification}"`,
        label: verificationLabel(verification),
        count: counts.verification[verification]
      })),
      counts.total,
      verificationDescription
    )}
  </div>
  <div class="numbers">${numbers
    .map(
      ([key, label, value, tone]) =>
        `<div class="num"><small>${esc(label)}</small><b data-stat="${key}"${tone ? ` data-tone="${tone}"` : ""}>${value}</b></div>`
    )
    .join("")}</div>
  ${mismatch}`;
}

function overviewSection(report: ViewableReport, facts: ReportFacts): string {
  const paragraphs = executiveSummary(report);
  return `<section class="section" id="overview" aria-labelledby="overview-heading">
    <h2 id="overview-heading">Overview</h2>
    <div class="summary">${paragraphs
      .map((paragraph, index) => `<p${index === 0 ? ` class="lede"` : ""}>${esc(paragraph)}</p>`)
      .join("")}</div>
    ${statsBlock(facts)}
  </section>`;
}

const RUN_MODE_LABEL: Record<ReportVerdict["runMode"], string> = {
  agent: "Agent-driven",
  static_only: "Static pass only",
  unattributed: "Agent not recorded"
};

/** `/myrqen` reads as a command, so it is set as one wherever the next step names it. */
function withCommands(text: string): string {
  return esc(text).replace(/(^|\s)(\/myrqen)\b/g, "$1<code>$2</code>");
}

function fixFirstItem(item: ReportVerdict["fixFirst"][number]): string {
  const where = [item.location, item.route].filter(Boolean).join("  ·  ");
  return `<li data-finding-id="${esc(item.findingId)}">
      <div class="marks">${severityChip(item.severity)}${verificationChip(item.verification)}</div>
      <div>
        <a class="ff-title" href="#${esc(item.findingId)}"><span class="fid">${esc(item.findingId)}</span>${esc(item.title)}</a>
        <div class="where">${esc(where)}</div>
        <p class="why">${esc(item.why)}</p>
      </div>
      <button class="copy" type="button" data-copy-text="${esc(item.fixPrompt)}" aria-label="Copy fix prompt for ${esc(item.findingId)}">Copy fix prompt</button>
    </li>`;
}

/**
 * The first thing on the page: one line that answers "do I have to fix something,
 * and how sure is this", then the three findings to start with. Every number in it
 * comes from the same counts as the rest of the report.
 */
function verdictSection(verdict: ReportVerdict): string {
  const fixFirst =
    verdict.fixFirst.length > 0
      ? `<h3>Fix these first</h3><ol class="fixfirst">${verdict.fixFirst.map(fixFirstItem).join("")}</ol>`
      : "";
  return `<section class="section verdict" id="verdict" data-tone="${esc(verdict.tone)}" data-run="${esc(verdict.runMode)}" aria-labelledby="verdict-heading">
    <p class="eyebrow">Verdict <span class="runmode">${esc(RUN_MODE_LABEL[verdict.runMode])}</span></p>
    <h2 id="verdict-heading">${esc(verdict.headline)}</h2>
    ${verdict.detail ? `<p class="verdict-detail">${esc(verdict.detail)}</p>` : ""}
    ${verdict.nextStep ? `<p class="verdict-next"><b>Next step</b>${withCommands(verdict.nextStep)}</p>` : ""}
    ${fixFirst}
    <p class="caveat">${esc(verdict.caveat)}</p>
  </section>`;
}

/** A list of identifiers that wraps between items, never inside one. */
function nowrapList(items: string[]): string {
  return items.length > 0 ? items.map((item) => `<span class="nw">${esc(item)}</span>`).join(", ") : "—";
}

function complianceSection(findings: Finding[]): string {
  if (findings.length === 0) return "";
  const rows = aggregateCompliance(findings);
  return `<section class="section" id="compliance" aria-labelledby="compliance-heading">
    <h2 id="compliance-heading">Compliance</h2>
    <p class="say">The findings in this report grouped by OWASP Top 10:2025, with the CWE weaknesses and OWASP ASVS requirements behind them. A finding that maps to two categories appears under both. A mapping says which control a finding concerns; it is not an audit of the rest of the standard.</p>
    <div class="tablewrap" tabindex="0" role="group" aria-label="Compliance mapping">
      <table>
        <thead><tr><th scope="col">OWASP Top 10:2025</th><th scope="col">Findings</th><th scope="col">CWE</th><th scope="col">ASVS</th></tr></thead>
        <tbody>${rows
          .map(
            (row) => `<tr>
          <td>${row.id === "unmapped" ? esc(row.title) : `<b>${esc(row.id)}</b> ${esc(row.title)}`}</td>
          <td class="mono">${row.findingIds.map((id) => `<a class="nw" href="#${esc(id)}">${esc(id)}</a>`).join(", ")}</td>
          <td class="mono">${nowrapList(row.cwe)}</td>
          <td class="mono">${nowrapList(row.asvs.map(asvsLabel))}</td>
        </tr>`
          )
          .join("")}</tbody>
      </table>
    </div>
  </section>`;
}

function baselineSection(baseline: ReportBaselineRecord | undefined): string {
  if (!baseline) return "";
  const fixed =
    baseline.fixed.length > 0
      ? `<div class="card" style="margin-top:12px"><h3>Gone since the baseline</h3><ul class="list">${baseline.fixed
          .map(
            (entry) =>
              `<li><b>${esc(entry.title)}</b> — ${esc(entry.severity)} · ${esc(humanize(entry.category))}${entry.file ? ` · ${esc(entry.file)}` : ""}${entry.route ? ` · ${esc(entry.route)}` : ""}</li>`
          )
          .join("")}</ul></div>`
      : "";
  return `<section class="section" id="baseline" aria-labelledby="baseline-heading">
    <h2 id="baseline-heading">Baseline</h2>
    <p class="say">Compared with the baseline taken ${esc(baseline.createdAt.slice(0, 10))}${baseline.fromReportId ? ` from ${esc(baseline.fromReportId)}` : ""}. A finding that is gone was not reported by this scan; that is not the same as verified fixed.</p>
    <div class="numbers">
      <div class="num"><small>New since baseline</small><b data-stat="baseline-new">${baseline.counts.new}</b></div>
      <div class="num"><small>Already in baseline</small><b data-stat="baseline-unchanged">${baseline.counts.unchanged}</b></div>
      <div class="num"><small>Gone since baseline</small><b data-stat="baseline-fixed">${baseline.counts.fixed}</b></div>
    </div>
    ${fixed}
  </section>`;
}

function chipGroup(group: string, label: string, values: Array<[string, string]>): string {
  return `<div class="fgroup" role="group" aria-label="${esc(label)}">
      <span class="flabel" aria-hidden="true">${esc(label)}</span>
      ${values
        .map(
          ([value, text], index) =>
            `<button class="chip" type="button" data-group="${esc(group)}" data-value="${esc(value)}" aria-pressed="${index === 0 ? "true" : "false"}">${esc(text)}</button>`
        )
        .join("")}
    </div>`;
}

/**
 * Everything the toolbar does is show and hide what is already on the page. The file
 * is read offline, from disk, with no server behind it, so a control that fetched a
 * missing finding would simply never resolve.
 */
function toolbarBlock(findings: Finding[]): string {
  const severities = SEVERITY_ORDER.filter((severity) => findings.some((finding) => finding.severity === severity));
  const verifications = VERIFICATION_ORDER.filter((verification) =>
    findings.some((finding) => finding.verification === verification)
  );
  const components = [...new Set(findings.map((finding) => finding.affected.component))].sort((a, b) =>
    a.localeCompare(b)
  );
  const fixed = findings.filter((finding) => findingState(finding) === "fixed").length;

  const stateValues: Array<[string, string]> = [
    ["all", "All"],
    ["open", `Open (${findings.length - fixed})`],
    ["fixed", `Fixed (${fixed})`]
  ];

  return `<form class="toolbar" role="search" aria-label="Find and filter findings" onsubmit="return false">
    <div class="searchrow">
      <label class="sr" for="finding-search">Search findings by title, route, file, or category</label>
      <input class="search" id="finding-search" type="search" autocomplete="off" placeholder="Search title, route, file, or category">
      <p class="count" id="shown-status" role="status" aria-live="polite">Showing <b>${findings.length}</b> of ${findings.length} findings</p>
    </div>
    <div class="filterrow">
      ${chipGroup("sev", "Severity", [["all", "All"], ...severities.map((severity) => [severity, severity] as [string, string])])}
      ${chipGroup("ver", "Verification", [
        ["all", "All"],
        ...verifications.map((verification) => [verification, verificationLabel(verification)] as [string, string])
      ])}
      ${chipGroup("state", "Status", stateValues)}
      <div class="selectwrap">
        <label class="flabel" for="component-filter">Component</label>
        <select class="filter" id="component-filter">
          <option value="all">All components (${components.length})</option>
          ${components.map((component) => `<option value="${esc(component)}">${esc(component)}</option>`).join("")}
        </select>
      </div>
    </div>
    <dl class="legend">
      ${VERIFICATION_ORDER.filter((verification) => verifications.includes(verification))
        .map(
          (verification) =>
            `<div><dt><span class="ver" data-ver="${verification}"><span aria-hidden="true">${VERIFICATION_GLYPH[verification]}</span>${esc(verificationLabel(verification))}</span></dt><dd>${esc(VERIFICATION_MEANING[verification])}</dd></div>`
        )
        .join("")}
    </dl>
  </form>`;
}

interface FindingsSectionInput {
  id: string;
  heading: string;
  say: string;
  findings: Finding[];
  rank: "lead" | "standard";
  emptyLine: string;
  openFirst: boolean;
  promptAvailable: boolean;
}

function findingsSection(input: FindingsSectionInput): string {
  const body =
    input.findings.length > 0
      ? `<div class="findings">${input.findings
          .map((finding, index) =>
            findingBlock(finding, {
              rank: input.rank,
              open: input.openFirst && index === 0,
              promptAvailable: input.promptAvailable
            })
          )
          .join("")}</div>`
      : `<p class="calm">${esc(input.emptyLine)}</p>`;

  return `<section class="section" id="${esc(input.id)}" data-findings-section="true" aria-labelledby="${esc(input.id)}-heading">
    <h2 id="${esc(input.id)}-heading">${esc(input.heading)}</h2>
    <p class="say">${esc(input.say)}</p>
    ${body}
  </section>`;
}

function remediationSection(findings: Finding[], promptAvailable: boolean): string {
  const open = findings.filter((finding) => findingState(finding) === "open");
  const fixed = findings.filter((finding) => findingState(finding) === "fixed");
  if (open.length === 0 && fixed.length === 0) return "";

  const rows = open
    .map(
      (finding, index) => `<tr>
      <td class="mono">${index + 1}</td>
      <td><a href="#${esc(finding.id)}">${esc(finding.id)}</a><div class="where">${esc(finding.affected.file ?? finding.affected.component)}</div></td>
      <td>${esc(finding.title)}</td>
      <td class="fixlist">${esc(finding.remediation)}</td>
      <td>${promptAvailable ? `<button class="copy secondary tiny" type="button" data-prompt-for="${esc(finding.id)}">Copy prompt</button>` : ""}</td>
    </tr>`
    )
    .join("");

  const fixedBlock =
    fixed.length > 0
      ? `<div class="card" style="margin-top:12px"><h3>Already fixed and verified</h3><ul class="list">${fixed
          .map(
            (finding) =>
              `<li><b>${esc(finding.id)}</b> — ${esc(finding.title)}${finding.fixedAt ? ` · ${esc(finding.fixedAt)}` : ""}</li>`
          )
          .join("")}</ul></div>`
      : "";

  return `<section class="section" id="remediation" aria-labelledby="remediation-heading">
    <h2 id="remediation-heading">Remediation</h2>
    <p class="say">The order below is the report's own: worse severity first, and within a severity the findings that are already proven. Each prompt carries that finding's evidence, its fix, and the check that has to pass before it counts as fixed.</p>
    ${
      open.length > 0
        ? `<div class="tablewrap" tabindex="0" role="group" aria-label="Remediation order">
      <table>
        <thead><tr><th scope="col">#</th><th scope="col">Finding</th><th scope="col">Title</th><th scope="col">What to change</th><th scope="col"></th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`
        : `<p class="calm">Every finding in this report is recorded as fixed and verified.</p>`
    }
    ${fixedBlock}
  </section>`;
}

function coverageSection(report: ViewableReport): string {
  const parts: string[] = [];
  if (report.coverage && report.coverage.length > 0) {
    parts.push(
      `<div class="card"><h3>Assessed</h3><ul class="list">${report.coverage
        .map((line) => `<li>${esc(line)}</li>`)
        .join("")}</ul></div>`
    );
  }
  if (report.coverageAreas && report.coverageAreas.length > 0) {
    parts.push(
      `<div class="card"><h3>Coverage by area</h3><ul class="list">${report.coverageAreas
        .map(
          (area) =>
            `<li><b class="${area.assessed ? "covered" : "notcovered"}">${area.assessed ? "assessed" : "not assessed"}</b> — ${esc(area.area)}${area.method ? ` · ${esc(area.method)}` : ""}${area.note ? ` · ${esc(area.note)}` : ""}</li>`
        )
        .join("")}</ul></div>`
    );
  }
  if (parts.length === 0) return "";
  return `<section class="section" id="coverage" aria-labelledby="coverage-heading">
    <h2 id="coverage-heading">Coverage</h2>
    <p class="say">What this assessment actually looked at. A finding can only come from something in this list.</p>
    <div class="cards">${parts.join("")}</div>
  </section>`;
}

function limitationsSection(report: ViewableReport): string {
  if (!report.limitations || report.limitations.length === 0) return "";
  return `<section class="section" id="limitations" aria-labelledby="limitations-heading">
    <h2 id="limitations-heading">Limitations</h2>
    <p class="say">What this assessment could not reach, recorded as the scan recorded it. Read this before treating the result as complete.</p>
    <div class="card"><ul class="list">${report.limitations.map((line) => `<li>${esc(line)}</li>`).join("")}</ul></div>
  </section>`;
}

function scanCards(report: ViewableReport, facts: ReportFacts, options: RenderOptions): string {
  const scan = report.scan;
  if (!scan) return "";
  const rows: Array<[string, string]> = [
    ["Effort requested", scan.effortRequested],
    ["Effort resolved", scan.effortResolved],
    ["Host agent", facts.run.agentLabel],
    ["Model", facts.run.modelLabel],
    ["Duration", facts.durationLabel ?? "unknown"],
    ["Token usage", formatTokenUsage(scan.tokenUsage)]
  ];
  if (scan.host) {
    rows.push(["Platform", `${scan.host.osFamily} ${scan.host.arch}`]);
    rows.push([
      "Isolated runtime",
      scan.host.isolatedRuntimeAvailable === undefined
        ? "unknown"
        : scan.host.isolatedRuntimeAvailable
          ? "available"
          : "not available on this machine"
    ]);
    if (scan.host.runtimeVersion) rows.push(["Runtime", scan.host.runtimeVersion]);
    if (scan.host.cliVersion) rows.push([`${BRAND.displayName} version`, scan.host.cliVersion]);
  }
  if (scan.stack) {
    if (scan.stack.frameworks.length > 0) rows.push(["Frameworks", scan.stack.frameworks.join(", ")]);
    if (scan.stack.languages.length > 0) rows.push(["Languages", scan.stack.languages.join(", ")]);
    if (scan.stack.packageManagers.length > 0) rows.push(["Package managers", scan.stack.packageManagers.join(", ")]);
  }
  if (scan.effortProfile) {
    rows.push(["Reasoning passes", String(scan.effortProfile.reasoningPasses)]);
    rows.push(["Validation passes", String(scan.effortProfile.validationPasses)]);
    rows.push(["False-positive challenge", scan.effortProfile.falsePositiveChallengePass ? "ran" : "did not run"]);
  }
  if (options.expiresAt) rows.push(["Cloud copy expires", options.expiresAt]);

  const prohibited = report.authorization?.prohibitedActions ?? [];
  const scope = `<div class="card"><h3>Scope and authorization</h3><dl class="kv">
    <dt>Local targets</dt><dd class="mono">${scan.scope.localTargets.length > 0 ? esc(scan.scope.localTargets.join(", ")) : "none recorded"}</dd>
    <dt>External targets</dt><dd class="mono">${
      scan.scope.externalTargets.length > 0
        ? esc(scan.scope.externalTargets.map((target) => target.target).join(", "))
        : "none authorized"
    }</dd>
    <dt>Destructive actions</dt><dd>not permitted</dd>
    <dt>External authorization</dt><dd>exact origin only</dd>
  </dl>${
    report.authorization?.notes?.length
      ? `<ul class="list">${report.authorization.notes.map((note) => `<li>${esc(note)}</li>`).join("")}</ul>`
      : ""
  }${
    prohibited.length > 0
      ? `<p class="blocknote">Refused for the whole run: ${esc(prohibited.map(humanize).join(", "))}.</p>`
      : ""
  }</div>`;

  return `<div class="cards">
    <div class="card"><h3>Scan</h3><dl class="kv">${rows
      .map(([key, value]) => `<dt>${esc(key)}</dt><dd>${esc(value)}</dd>`)
      .join("")}</dl></div>
    ${scope}
  </div>`;
}

function phasesBlock(report: ViewableReport): string {
  const phases = report.scan?.phases;
  if (!phases || phases.length === 0) return "";
  return `<div class="tablewrap" tabindex="0" role="group" aria-label="Scan phases" style="margin-top:12px">
    <table>
      <thead><tr><th scope="col">Phase</th><th scope="col">State</th><th scope="col">Duration</th><th scope="col">Note</th></tr></thead>
      <tbody>${phases
        .map(
          (phase) =>
            `<tr><td>${esc(humanize(phase.phase))}</td><td>${esc(phase.state)}</td><td class="mono">${phase.durationMs === undefined ? "—" : esc(formatDuration(phase.durationMs))}</td><td>${esc(phase.note ?? "")}</td></tr>`
        )
        .join("")}</tbody>
    </table>
  </div>`;
}

function metadataSection(report: ViewableReport, facts: ReportFacts, options: RenderOptions): string {
  const canonical = report as ScanReport;
  const cards = scanCards(report, facts, options);
  const methodology = canonical.methodologyVersion
    ? `<div class="card" style="margin-top:12px"><h3>Methodology, version ${esc(canonical.methodologyVersion)}</h3><ul class="list">
      <li>Preflight and authorization boundaries, then application mapping.</li>
      <li>Source, configuration, and dependency review for plausible root causes.</li>
      <li>Controlled dynamic validation against authorized targets only.</li>
      <li>Access-control comparison across the available test identities.</li>
      <li>Validation, deduplication, and a false-positive challenge pass.</li>
      <li>Remediation guidance with a targeted verification step per finding.</li>
    </ul></div>`
    : "";
  if (cards === "" && methodology === "") return "";
  return `<section class="section" id="metadata" aria-labelledby="metadata-heading">
    <h2 id="metadata-heading">Technical metadata</h2>
    <p class="say">How this assessment ran, and under what authorization.</p>
    ${cards}
    ${phasesBlock(report)}
    ${methodology}
  </section>`;
}

interface TocEntry {
  id: string;
  label: string;
  count?: number;
}

function tocBlock(entries: TocEntry[]): string {
  return `<nav class="toc" aria-label="Report sections">
    <ol>${entries
      .map(
        (entry) =>
          `<li><a href="#${esc(entry.id)}">${esc(entry.label)}${entry.count !== undefined ? `<span class="n">${entry.count}</span>` : ""}</a></li>`
      )
      .join("")}</ol>
  </nav>`;
}

/* ------------------------------------------------------------------ *
 * Behaviour
 * ------------------------------------------------------------------ */


/* ------------------------------------------------------------------ *
 * Document
 * ------------------------------------------------------------------ */

const NO_FINDINGS_TITLE = "No findings were reported";
const NO_FINDINGS_BODY =
  "This is not evidence that the application is secure. Read the coverage and the limitations below to see what was assessed and what was not.";

const PRIORITY_SAY =
  "Critical and high findings that were demonstrated or carry strong evidence. If only part of this report gets acted on today, it should be this part.";
const PRIORITY_EMPTY =
  "No finding in this report is both critical or high and backed by verified or strong evidence. The findings below are still worth reading.";
const VERIFIED_SAY =
  "Demonstrated against this application in the same way as the section above, at a lower severity.";
const VERIFIED_EMPTY = "Nothing else in this report was demonstrated outright.";
const OTHER_SAY =
  "Strong evidence without full proof, findings that still need review, and anything already closed out. The verification line on each one says how far it was taken.";
const OTHER_EMPTY = "Every finding in this report is either demonstrated or already listed above.";

/**
 * Self-contained offline HTML. No network requests, no external fonts, no
 * trackers: everything needed to read the report is in this one file.
 *
 * The page is ordered as a reader's questions arrive — what happened, what matters
 * most, what is proven, what is not, what to do, what was covered, what was missed,
 * how it ran — rather than as the data model is shaped.
 */
export function renderStandaloneHtml(report: ViewableReport, options: RenderOptions = {}): string {
  const findingsAvailable = Array.isArray(report.findings);
  const findings = sortFindings(report.findings ?? []);
  const promptAvailable = findingsAvailable;
  const forceOpen = options.print === true;

  const prompts: Record<string, string> = {};
  if (promptAvailable) {
    for (const finding of findings) {
      const context: { projectName?: string; localReportId?: string } = { localReportId: report.id };
      if (report.project?.name) context.projectName = report.project.name;
      prompts[finding.id] = buildFixPrompt(finding, context);
    }
  }

  const facts = reportFacts(report);
  const verdict = buildVerdict(report);
  const projectName = report.project?.name ?? `${BRAND.displayName} report`;
  const stateLabel = options.contextLabel ?? "Local report";
  const subline = [
    report.project?.workspaceName ? `${report.project.workspaceName} workspace` : null,
    report.scan ? `${report.scan.effortResolved} effort` : null,
    report.scan ? facts.run.agentLabel : null,
    facts.durationLabel,
    facts.generatedLabel ? `generated ${facts.generatedLabel}` : null
  ]
    .filter(Boolean)
    .join("  ·  ");

  const buckets = bucketFindings(findings);
  const toc: TocEntry[] = [
    { id: "verdict", label: "Verdict" },
    { id: "overview", label: "Overview" }
  ];
  const body: string[] = [verdictSection(verdict), overviewSection(report, facts)];
  const baseline = baselineSection(report.baseline);
  if (baseline !== "") {
    body.push(baseline);
    toc.push({ id: "baseline", label: "Baseline" });
  }

  if (findings.length > 0) {
    body.push(toolbarBlock(findings));
    body.push(
      `<div class="empty" id="filter-empty" hidden><b>No findings match these filters</b><p>Every finding is still in this file. Clear a filter to bring the rest back.</p><div class="actions"><button class="copy secondary" type="button" id="clear-filters">Clear filters</button></div></div>`
    );

    const findingSections: FindingsSectionInput[] = [
      {
        id: "priority",
        heading: "What matters most",
        say: PRIORITY_SAY,
        findings: buckets.priority,
        rank: "lead",
        emptyLine: PRIORITY_EMPTY,
        openFirst: !forceOpen,
        promptAvailable
      },
      {
        id: "verified",
        heading: "Verified findings",
        say: VERIFIED_SAY,
        findings: buckets.verified,
        rank: "standard",
        emptyLine: VERIFIED_EMPTY,
        openFirst: false,
        promptAvailable
      },
      {
        id: "other",
        heading: "Other findings",
        say: OTHER_SAY,
        findings: buckets.other,
        rank: "standard",
        emptyLine: OTHER_EMPTY,
        openFirst: false,
        promptAvailable
      }
    ];

    for (const section of findingSections) {
      // Every section is printed even when empty: a reader who sees "Verified
      // findings" with one calm sentence under it learns something a missing
      // heading would have hidden.
      body.push(findingsSection(forceOpen ? { ...section, openFirst: true } : section));
      toc.push({ id: section.id, label: section.heading, count: section.findings.length });
    }

    const remediation = remediationSection(findings, promptAvailable);
    if (remediation !== "") {
      body.push(remediation);
      toc.push({ id: "remediation", label: "Remediation" });
    }
  } else if (findingsAvailable) {
    body.push(
      `<section class="section" id="findings" aria-labelledby="findings-heading">
        <h2 id="findings-heading">Findings</h2>
        <div class="empty"><b>${esc(NO_FINDINGS_TITLE)}</b><p>${esc(NO_FINDINGS_BODY)}</p></div>
      </section>`
    );
    toc.push({ id: "findings", label: "Findings", count: 0 });
  }

  const compliance = complianceSection(findings);
  if (compliance !== "") {
    body.push(compliance);
    toc.push({ id: "compliance", label: "Compliance" });
  }
  const coverage = coverageSection(report);
  if (coverage !== "") {
    body.push(coverage);
    toc.push({ id: "coverage", label: "Coverage" });
  }
  const limitations = limitationsSection(report);
  if (limitations !== "") {
    body.push(limitations);
    toc.push({ id: "limitations", label: "Limitations" });
  }
  const metadata = metadataSection(report, facts, options);
  if (metadata !== "") {
    body.push(metadata);
    toc.push({ id: "metadata", label: "Technical metadata" });
  }

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta name="robots" content="noindex, nofollow">
<title>${esc(BRAND.displayName)} report — ${esc(projectName)}</title>
<style>${REPORT_STYLES}${CODE_STYLES}</style>
</head>
<body>
<a class="skip" href="#verdict">Skip to the verdict</a>
<div class="page">
  <header>
    <div class="brandline">
      <div class="wordmark">${esc(BRAND.uppercaseName)}<span>authorized application security assessment</span></div>
      <div class="state">${esc(stateLabel)}</div>
    </div>
    <h1>${esc(projectName)}</h1>
    <p class="sub">${esc(subline)}</p>
    ${options.notice ? `<p class="notice">${esc(options.notice)}</p>` : ""}
    ${report.redactionNotice ? `<p class="notice">${esc(report.redactionNotice)}</p>` : ""}
  </header>

  <div class="shell">
    ${tocBlock(toc)}
    <main class="main">${body.join("\n")}</main>
  </div>

  <footer>
    <span>${esc(BRAND.reportFooter)}</span>
    <span>Report ${esc(report.id)} · schema ${esc(report.schemaVersion ?? BRAND.reportSchemaVersion)}${options.cloudUrl ? ` · ${esc(options.cloudUrl)}` : ""}</span>
  </footer>
</div>
<div class="toast" id="toast" role="status" aria-live="polite"></div>
<script type="application/json" id="myrqen-fix-prompts">${jsonForScript(prompts)}</script>
<script>${REPORT_SCRIPT}</script>
</body>
</html>
`;
}
