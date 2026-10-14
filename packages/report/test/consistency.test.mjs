import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  buildReport,
  buildVerdict,
  countFindings,
  executiveSummary,
  formatTimestamp,
  reportFacts,
  renderMarkdown,
  renderSarif,
  renderStandaloneHtml
} from "../dist/index.js";
import { projectReport } from "../../policy/dist/index.js";
import { validateReport } from "../../contracts/dist/index.js";

/**
 * Every format is a view of one report, so every number in every format has to be
 * the same number. These tests read the counts back out of each rendered artifact
 * and hold them to `countFindings`, the single function the renderers count with.
 *
 * Two real reports are used: one an agent drove (findings verified against a
 * running app) and one the CLI produced on its own with no agent at all — the run
 * that used to print "unknown" where the agent goes.
 */
function load(name) {
  return JSON.parse(readFileSync(fileURLToPath(new URL(`./fixtures/${name}.json`, import.meta.url)), "utf8"));
}

/** Rebuild through `buildReport` so the stored summary is the one this code writes. */
function rebuilt(raw) {
  return buildReport({
    id: raw.id,
    generatedAt: new Date(raw.generatedAt),
    project: raw.project,
    scan: raw.scan,
    findings: raw.findings,
    coverage: raw.coverage,
    limitations: raw.limitations,
    ...(raw.summary.candidateCount !== undefined ? { candidateCount: raw.summary.candidateCount } : {}),
    ...(raw.summary.duplicateCount !== undefined ? { duplicateCount: raw.summary.duplicateCount } : {})
  });
}

const AGENT = rebuilt(load("vuln-shop-report"));
const STATIC = rebuilt(load("vuln-shop-static-report"));
const REPORTS = [
  ["agent-driven", AGENT],
  ["static-only", STATIC]
];

const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const VERIFICATIONS = ["verified", "strong_evidence", "needs_review"];

/* ---------- reading the numbers back out of each format ---------- */

function htmlStat(html, key) {
  const match = new RegExp(`data-stat="${key}"[^>]*>(\\d+)<`).exec(html);
  return match ? Number(match[1]) : null;
}

function htmlBar(html, attribute, value) {
  const match = new RegExp(`<li[^>]*${attribute}="${value}"[^>]*>.*?<b>(\\d+)</b>`).exec(html);
  return match ? Number(match[1]) : null;
}

function markdownSeverity(markdown, severity) {
  const match = new RegExp(`^\\| ${severity} \\| (\\d+) \\|`, "m").exec(markdown);
  return match ? Number(match[1]) : null;
}

function markdownVerification(markdown) {
  const match = /Verified: (\d+) · Strong evidence: (\d+) · Needs review: (\d+)/.exec(markdown);
  return match ? { verified: +match[1], strong_evidence: +match[2], needs_review: +match[3] } : null;
}

const WORDS = ["no", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "eleven", "twelve", "thirteen", "fourteen", "fifteen", "sixteen", "seventeen", "eighteen", "nineteen", "twenty"];

for (const [label, report] of REPORTS) {
  const counts = countFindings(report.findings);

  test(`${label}: the stored summary is what countFindings says`, () => {
    assert.equal(validateReport(report).valid, true);
    assert.equal(report.summary.findingCount, counts.total);
    assert.deepEqual(report.summary.severityCounts, counts.severity);
    assert.deepEqual(report.summary.verificationCounts, counts.verification);
    assert.equal(report.summary.fixedCount, counts.fixed);
    const severitySum = SEVERITIES.reduce((sum, severity) => sum + counts.severity[severity], 0);
    const verificationSum = VERIFICATIONS.reduce((sum, verification) => sum + counts.verification[verification], 0);
    assert.equal(severitySum, counts.total, "severity totals add up to the finding count");
    assert.equal(verificationSum, counts.total, "verification totals add up to the finding count");
  });

  test(`${label}: HTML stat cards, bars, prose, and verdict agree with the counts`, () => {
    const html = renderStandaloneHtml(report);
    assert.equal(htmlStat(html, "findings"), counts.total);
    assert.equal(htmlStat(html, "verified"), counts.verification.verified);
    assert.equal(htmlStat(html, "fixed"), counts.fixed);
    for (const severity of SEVERITIES) assert.equal(htmlBar(html, "data-sev", severity), counts.severity[severity], severity);
    for (const verification of VERIFICATIONS) {
      assert.equal(htmlBar(html, "data-ver", verification), counts.verification[verification], verification);
    }
    const prose = executiveSummary(report).join(" ");
    const word = WORDS[counts.total] ?? String(counts.total);
    assert.match(prose, new RegExp(`\\b${word} findings? (is|are) recorded`, "i"));
    // The headline figure is printed, never animated up from zero: a screenshot,
    // a print, or a backgrounded tab must never show a smaller number.
    assert.doesNotMatch(html, /requestAnimationFrame\(step\)|tween\(/);
  });

  test(`${label}: Markdown tables agree with the counts`, () => {
    const markdown = renderMarkdown(report);
    for (const severity of SEVERITIES) assert.equal(markdownSeverity(markdown, severity), counts.severity[severity], severity);
    assert.deepEqual(markdownVerification(markdown), counts.verification);
    assert.match(markdown, new RegExp(`Findings: ${counts.total}\\b`));
  });

  test(`${label}: SARIF carries one result per finding and the same totals`, () => {
    const sarif = JSON.parse(renderSarif(report));
    const run = sarif.runs[0];
    assert.equal(run.results.length, counts.total);
    assert.equal(run.properties.myrqen.findingCount, counts.total);
    assert.deepEqual(run.properties.myrqen.severityCounts, counts.severity);
    assert.deepEqual(run.properties.myrqen.verificationCounts, counts.verification);
    for (const severity of SEVERITIES) {
      assert.equal(run.results.filter((result) => result.properties.severity === severity).length, counts.severity[severity]);
    }
  });

  test(`${label}: the verdict is the same in JSON, HTML, Markdown, and SARIF`, () => {
    const verdict = buildVerdict(report);
    assert.equal(report.verdict.headline, verdict.headline);
    assert.deepEqual(report.verdict.fixFirst.map((item) => item.findingId), verdict.fixFirst.map((item) => item.findingId));
    const html = renderStandaloneHtml(report);
    const markdown = renderMarkdown(report);
    const escapedHeadline = verdict.headline.replaceAll("'", "&#39;");
    assert.ok(html.includes(escapedHeadline), "HTML prints the verdict headline");
    assert.ok(markdown.includes(verdict.headline), "Markdown prints the verdict headline");
    assert.equal(JSON.parse(renderSarif(report)).runs[0].properties.myrqen.verdict, verdict.headline);
  });

  test(`${label}: duration and generated time are spelled the same everywhere`, () => {
    const facts = reportFacts(report);
    const html = renderStandaloneHtml(report);
    const markdown = renderMarkdown(report);
    const generated = formatTimestamp(report.generatedAt);
    assert.ok(html.includes(generated));
    assert.ok(markdown.includes(generated));
    assert.ok(html.includes(facts.durationLabel));
    assert.ok(markdown.includes(`Duration: ${facts.durationLabel}`));
  });
}

test("the verdict opens every human format", () => {
  for (const [, report] of REPORTS) {
    const html = renderStandaloneHtml(report);
    const verdictAt = html.indexOf('id="verdict"');
    assert.ok(verdictAt > 0, "HTML has a verdict section");
    assert.ok(verdictAt < html.indexOf('id="overview"'), "the verdict comes before the overview");
    const markdown = renderMarkdown(report);
    assert.ok(markdown.indexOf("## Verdict") > 0);
    assert.ok(markdown.indexOf("## Verdict") < markdown.indexOf("## Summary"));
    assert.ok(markdown.indexOf("## Verdict") < markdown.indexOf("## Findings"));
  }
});

test("a run no agent drove says so instead of 'unknown'", () => {
  const facts = reportFacts(STATIC);
  assert.equal(facts.run.mode, "static_only");
  const html = renderStandaloneHtml(STATIC);
  const markdown = renderMarkdown(STATIC);
  for (const text of [html, markdown]) {
    assert.match(text, /No agent — static pass only/);
    assert.doesNotMatch(text, /Host agent<\/dt><dd>unknown|Host agent: unknown|Model: unknown|>unknown</);
  }
  const verdict = buildVerdict(STATIC);
  assert.equal(verdict.runMode, "static_only");
  assert.match(verdict.headline, /none verified/);
  assert.match(verdict.headline, /no agent/i);
  assert.match(verdict.nextStep, /\/myrqen/);
  assert.match(verdict.nextStep, /Claude Code/);
  assert.ok(html.includes("/myrqen"));
  assert.ok(markdown.includes("/myrqen"));
});

test("an agent-driven run names its agent and model", () => {
  const facts = reportFacts(AGENT);
  assert.equal(facts.run.mode, "agent");
  assert.equal(facts.run.agentLabel, AGENT.scan.agent.name);
  const verdict = buildVerdict(AGENT);
  assert.equal(verdict.tone, "verified_risk");
  assert.doesNotMatch(verdict.headline, /no agent/i);
});

test("every format carries the binding honesty line", () => {
  for (const [, report] of REPORTS) {
    const caveat = "A clean report is not evidence that an application is secure";
    assert.ok(renderStandaloneHtml(report).includes(caveat));
    assert.ok(renderMarkdown(report).includes(caveat));
    assert.ok(report.verdict.caveat.includes(caveat));
  }
});

test("a projection's counts describe only what the viewer can see", () => {
  const policy = {
    version: 1,
    sections: { mode: "allow_all", ids: [] },
    findings: { mode: "allow_only", ids: ["MYR-004", "MYR-011"] },
    fields: {},
    anonymize: false
  };
  const projected = projectReport(AGENT, policy);
  const counts = countFindings(projected.findings);
  assert.equal(counts.total, 2);
  const html = renderStandaloneHtml(projected);
  assert.equal(htmlStat(html, "findings"), 2);
  const verdict = buildVerdict(projected);
  for (const item of verdict.fixFirst) assert.ok(["MYR-004", "MYR-011"].includes(item.findingId));
  assert.doesNotMatch(html, /MYR-006/);
  assert.doesNotMatch(renderMarkdown(projected), /MYR-006/);
});
