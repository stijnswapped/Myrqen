import { test } from "node:test";
import assert from "node:assert/strict";
import { buildQuickFixPrompt, buildVerdict, oneLine, priorityScore, rankForFixing } from "../dist/index.js";

function finding(overrides = {}) {
  return {
    id: "MYR-001",
    title: "Order ownership is not enforced",
    category: "broken_object_level_authorization",
    severity: "high",
    verification: "verified",
    summary: "The order route loads the record by identifier without scoping it to the authenticated subject.",
    impact: "A signed-in user can read another account's order data. That includes addresses and totals.",
    affected: { component: "orders API", route: "GET /api/orders/:id", file: "src/routes/orders.ts", lineStart: 42 },
    evidence: [{ kind: "source", description: "The query has no ownership predicate." }],
    remediation: "Scope the query to the authenticated subject.",
    verificationPlan: "Repeat the cross-account request and assert a 403 or 404 response.",
    ...overrides
  };
}

const agentScan = { agent: { name: "Claude Code", model: "claude-opus-5" }, durationMs: 1000 };
const noAgentScan = { agent: { name: "unknown" }, durationMs: 1000 };

function view(findings, scan = agentScan) {
  return { id: "rpt_1", project: { name: "Shop" }, scan, findings };
}

test("proof discounts severity: a verified high outranks a critical on strong evidence", () => {
  assert.ok(priorityScore({ severity: "high", verification: "verified" }) > priorityScore({ severity: "critical", verification: "strong_evidence" }));
  assert.ok(priorityScore({ severity: "critical", verification: "strong_evidence" }) > priorityScore({ severity: "high", verification: "strong_evidence" }));
  assert.ok(priorityScore({ severity: "medium", verification: "strong_evidence" }) > priorityScore({ severity: "critical", verification: "needs_review" }));
});

test("fix-first lists at most three open findings, most urgent first", () => {
  const findings = [
    finding({ id: "A", severity: "critical", verification: "strong_evidence" }),
    finding({ id: "B", severity: "high", verification: "verified" }),
    finding({ id: "C", severity: "critical", verification: "verified", status: "fixed_verified" }),
    finding({ id: "D", severity: "low", verification: "verified" }),
    finding({ id: "E", severity: "medium", verification: "needs_review" }),
    finding({ id: "F", severity: "critical", verification: "needs_review", status: "false_positive" })
  ];
  assert.deepEqual(rankForFixing(findings).map((item) => item.id), ["B", "A", "D", "E"]);
  const verdict = buildVerdict(view(findings));
  assert.deepEqual(verdict.fixFirst.map((item) => item.findingId), ["B", "A", "D"]);
});

test("each fix-first entry carries severity, proof, place, a reason, and a prompt", () => {
  const verdict = buildVerdict(view([finding()]));
  const [first] = verdict.fixFirst;
  assert.equal(first.severity, "high");
  assert.equal(first.verification, "verified");
  assert.equal(first.location, "src/routes/orders.ts:42");
  assert.equal(first.route, "GET /api/orders/:id");
  assert.equal(first.why, "A signed-in user can read another account's order data.");
  assert.match(first.fixPrompt, /MYR-001/);
  assert.match(first.fixPrompt, /src\/routes\/orders\.ts:42/);
  assert.match(first.fixPrompt, /--session rpt_1 fix record MYR-001 --verified/);
});

test("a verified finding produces a ship-blocking verdict", () => {
  const verdict = buildVerdict(view([finding(), finding({ id: "MYR-002", verification: "needs_review" })]));
  assert.equal(verdict.tone, "verified_risk");
  assert.match(verdict.headline, /^1 verified vulnerability, the worst high — fix it before you ship\.$/);
  assert.match(verdict.detail, /2 open findings/);
});

test("unverified findings from an agent run are not called vulnerabilities", () => {
  const verdict = buildVerdict(view([finding({ verification: "strong_evidence" })]));
  assert.equal(verdict.tone, "unverified_risk");
  assert.equal(verdict.headline, "1 open finding, none verified yet.");
  assert.match(verdict.nextStep, /\/myrqen/);
});

test("with no agent, the verdict says nothing was verified and how to fix that", () => {
  const findings = [finding({ verification: "strong_evidence", tags: ["static-pass"] })];
  const verdict = buildVerdict(view(findings, noAgentScan));
  assert.equal(verdict.runMode, "static_only");
  assert.match(verdict.headline, /static pass — none verified, because no agent drove this run/);
  assert.match(verdict.nextStep, /Run \/myrqen inside your coding agent \(Claude Code, Codex/);
});

test("an empty report is clear but never called secure", () => {
  const verdict = buildVerdict(view([]));
  assert.equal(verdict.tone, "clear");
  assert.doesNotMatch(verdict.headline, /secure/i);
  assert.match(verdict.caveat, /not evidence that an application is secure/);
  const noAgent = buildVerdict(view([], noAgentScan));
  assert.match(noAgent.headline, /no agent/);
  assert.match(noAgent.nextStep, /\/myrqen/);
});

test("a report with everything closed says so", () => {
  const verdict = buildVerdict(view([finding({ status: "fixed_verified" })]));
  assert.equal(verdict.tone, "settled");
  assert.equal(verdict.fixFirst.length, 0);
});

test("a view without findings carries no verdict rather than a guessed one", () => {
  const verdict = buildVerdict({ id: "rpt_1", summary: { findingCount: 3, severityCounts: { critical: 0, high: 3, medium: 0, low: 0, info: 0 }, verificationCounts: { verified: 1, strong_evidence: 2, needs_review: 0 } } });
  assert.equal(verdict.tone, "withheld");
  assert.equal(verdict.fixFirst.length, 0);
  assert.match(verdict.detail, /3 findings/);
});

test("the quick prompt flags unconfirmed findings and committed secrets", () => {
  assert.match(buildQuickFixPrompt(finding({ verification: "needs_review" })), /unconfirmed/);
  assert.doesNotMatch(buildQuickFixPrompt(finding()), /unconfirmed/);
  assert.match(buildQuickFixPrompt(finding({ category: "hardcoded_secret" })), /Rotate the credential/);
});

test("one-line reasons stop at the first sentence and never run on", () => {
  assert.equal(oneLine("First. Second."), "First.");
  const long = `${"word ".repeat(80)}end.`;
  const line = oneLine(long);
  assert.ok(line.length <= 181, `${line.length}`);
  assert.ok(line.endsWith("…"));
});

test("with no agent, a strong-evidence finding's quick prompt says it is unconfirmed", () => {
  const staticFinding = finding({ id: "S", verification: "strong_evidence", tags: ["static-pass"] });
  const verdict = buildVerdict(view([staticFinding], noAgentScan));
  assert.equal(verdict.runMode, "static_only");
  assert.match(verdict.fixFirst[0].fixPrompt, /unconfirmed/);
  const withAgent = buildVerdict(view([finding({ id: "S", verification: "strong_evidence" })]));
  assert.doesNotMatch(withAgent.fixFirst[0].fixPrompt, /unconfirmed/);
});
