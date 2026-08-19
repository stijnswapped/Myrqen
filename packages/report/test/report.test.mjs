import { test } from "node:test";
import assert from "node:assert/strict";
import { buildFixPrompt, buildReport, formatDuration, formatTokenUsage, renderMarkdown, renderSarif, renderStandaloneHtml, sortFindings } from "../dist/index.js";
import { projectReport } from "../../policy/dist/index.js";
import { validateReport } from "../../contracts/dist/index.js";

const CANARY = "myrqen-canary-2f8c1a94d7be4c5f9a13";

function finding(overrides = {}) {
  return {
    id: "MYR-001",
    title: "Order ownership is not enforced",
    category: "broken_object_level_authorization",
    severity: "high",
    verification: "verified",
    summary: "The order route loads the record by identifier without scoping it to the authenticated subject.",
    impact: "A signed-in user can read another account's order data by changing the identifier.",
    affected: { component: "orders API", route: "GET /api/orders/:id", file: "src/routes/orders.ts", lineStart: 42 },
    evidence: [
      { kind: "identity_differential", description: "User A received User B's fixture order with status 200." },
      { kind: "source", description: "The query has no ownership predicate.", snippet: "const order = await db.orders.find(id);" }
    ],
    remediation: "Scope the query to the authenticated subject or verify ownership before returning the record.",
    verificationPlan: "Repeat the cross-account request and assert a 403 or 404 response.",
    reproduction: "curl -H 'Cookie: session=<user-a>' http://127.0.0.1:4010/api/orders/2",
    fingerprint: "fp_abc123",
    ...overrides
  };
}

const scan = {
  effortRequested: "auto",
  effortResolved: "high",
  startedAt: "2026-08-18T09:00:00.000Z",
  completedAt: "2026-08-18T09:18:42.000Z",
  durationMs: 1_122_000,
  agent: { name: "Claude Code", version: "2.1.0", model: "claude-opus-5" },
  host: { osFamily: "darwin", arch: "arm64", cliVersion: "0.1.0", isolatedRuntimeAvailable: false },
  tokenUsage: { source: "estimated", count: 412_000, estimator: "transcript-v1" },
  scope: { localTargets: ["http://127.0.0.1:4010"], externalTargets: [] },
  stack: { languages: ["TypeScript"], frameworks: ["Express"], packageManagers: ["pnpm"], services: ["http://127.0.0.1:4010"] }
};

function report(overrides = {}) {
  return buildReport({
    id: "rpt_local_1",
    project: { name: "Checkout API", workspaceKind: "personal", workspaceName: "Personal" },
    scan,
    findings: [finding()],
    coverage: ["Source and configuration review", "Local runtime validation"],
    coverageAreas: [
      { area: "Object-level authorization", assessed: true, method: "identity differential" },
      { area: "Isolated runtime checks", assessed: false, note: "No isolated runtime on this machine" }
    ],
    limitations: ["Only two test identities were available."],
    candidateCount: 9,
    ...overrides
  });
}

test("a built report validates against the canonical schema", () => {
  const built = report();
  const result = validateReport(built);
  assert.equal(result.valid, true);
  assert.equal(built.summary.findingCount, 1);
  assert.equal(built.summary.severityCounts.high, 1);
  assert.equal(built.summary.verificationCounts.verified, 1);
  assert.equal(built.authorization.destructiveActionsAllowed, false);
  assert.equal(built.authorization.externalTargetAuthorization, "exact_origin_only");
});

test("an empty report explicitly refuses to imply the app is secure", () => {
  const built = report({ findings: [], limitations: [] });
  assert.match(built.limitations.join(" "), /not evidence that the application is secure/);
});

test("findings sort worst-first and verified-first", () => {
  const sorted = sortFindings([
    finding({ id: "A", severity: "low", verification: "verified" }),
    finding({ id: "B", severity: "critical", verification: "needs_review" }),
    finding({ id: "C", severity: "critical", verification: "verified" })
  ]);
  assert.deepEqual(sorted.map((item) => item.id), ["C", "B", "A"]);
});

test("local HTML is fully self-contained and makes no network request", () => {
  const html = renderStandaloneHtml(report());
  assert.match(html, /^<!doctype html>/);
  for (const pattern of [/https?:\/\/(?!127\.0\.0\.1|localhost)[a-z]/i]) {
    const matches = html.match(pattern);
    // The only external-looking strings permitted are inside report content and
    // the SARIF/site references, never as a resource reference.
    if (matches) {
      assert.ok(!/<(script|link|img|iframe|source|video|audio)[^>]+(src|href)=["']https?:/i.test(html), "no remote resources");
    }
  }
  assert.ok(!/<link[^>]+href=/i.test(html), "no external stylesheets");
  assert.ok(!/@import/i.test(html), "no CSS imports");
  assert.ok(!/fetch\(|XMLHttpRequest|WebSocket|EventSource/i.test(html), "no runtime network calls");
  assert.ok(!/<script[^>]+src=/i.test(html), "no external scripts");
  assert.match(html, /Copy prompt to fix/);
});

test("HTML escapes report content so it cannot inject markup", () => {
  const html = renderStandaloneHtml(
    report({ findings: [finding({ title: '</script><img src=x onerror="alert(1)">' })] })
  );
  assert.ok(!html.includes('<img src=x onerror="alert(1)">'));
  assert.match(html, /&lt;img src=x/);
});

test("HTML represents severity with text and a glyph, not colour alone", () => {
  const html = renderStandaloneHtml(report());
  assert.match(html, /class="sev" data-sev="high"[^>]*>.*high/s);
  assert.match(html, /Strong evidence|Verified|Needs review/);
});

test("fix prompt carries context and constraints and never a secret", () => {
  const prompt = buildFixPrompt(finding(), { projectName: "Checkout API", localReportId: "rpt_local_1" });
  assert.match(prompt, /MYR-001/);
  assert.match(prompt, /Required remediation/);
  assert.match(prompt, /Do not log, print, or hard-code any secret/);
  assert.match(prompt, /Do not mark this finding fixed unless/);
  assert.match(prompt, /src\/routes\/orders\.ts/);
  assert.ok(!prompt.includes(CANARY));
});

test("markdown export contains the findings and the coverage honesty note", () => {
  const markdown = renderMarkdown(report({ findings: [] }));
  assert.match(markdown, /# Myrqen security assessment/);
  assert.match(markdown, /not evidence that the application is secure/);

  const withFinding = renderMarkdown(report());
  assert.match(withFinding, /### MYR-001 — Order ownership is not enforced/);
  assert.match(withFinding, /Severity: \*\*high\*\*/);
});

test("SARIF export is conservative about rules and locations", () => {
  const sarif = JSON.parse(renderSarif(report()));
  assert.equal(sarif.version, "2.1.0");
  const run = sarif.runs[0];
  assert.equal(run.tool.driver.name, "Myrqen");
  assert.equal(run.tool.driver.rules.length, 1);
  assert.equal(run.tool.driver.rules[0].id, "myrqen/broken_object_level_authorization");
  assert.equal(run.results[0].level, "error");
  assert.equal(run.results[0].locations[0].physicalLocation.artifactLocation.uri, "src/routes/orders.ts");
  assert.equal(run.results[0].locations[0].physicalLocation.region.startLine, 42);
  assert.equal(run.results[0].partialFingerprints.myrqenFingerprint, "fp_abc123");
});

test("SARIF omits locations rather than inventing a line number", () => {
  const sarif = JSON.parse(
    renderSarif(report({ findings: [finding({ affected: { component: "dependency manifest" } })] }))
  );
  assert.deepEqual(sarif.runs[0].results[0].locations, []);
});

test("exports render the viewer projection, never the canonical report", () => {
  const canonical = report({
    findings: [finding({ id: "MYR-001" }), finding({ id: "MYR-002", title: "Second issue", category: "other_category", affected: { component: "second component" } })]
  });
  const policy = {
    version: 1,
    sections: { mode: "allow_only", ids: ["summary", "findings"] },
    findings: { mode: "allow_only", ids: ["MYR-002"] },
    fields: { evidence: false, code: false, metadata: false }
  };
  const projection = projectReport(canonical, policy, { principalType: "email", label: "bob@example.com" });

  const html = renderStandaloneHtml(projection);
  assert.ok(!html.includes("MYR-001"));
  assert.ok(!html.includes("const order = await db.orders.find(id);"));
  assert.match(html, /MYR-002/);

  const markdown = renderMarkdown(projection);
  assert.ok(!markdown.includes("MYR-001"));

  const sarif = renderSarif(projection);
  assert.ok(!sarif.includes("MYR-001"));
});

test("token provenance is always visible and never fabricated", () => {
  assert.equal(formatTokenUsage({ source: "unavailable" }), "Unavailable");
  assert.equal(formatTokenUsage({ source: "exact", count: 1000 }), "1,000 (exact)");
  assert.match(formatTokenUsage({ source: "estimated", count: 1000, estimator: "v1" }), /^~1,000 \(estimated, v1\)$/);

  const html = renderStandaloneHtml(report());
  assert.match(html, /estimated, transcript-v1/);
});

test("duration formatting is human readable", () => {
  assert.equal(formatDuration(45_000), "45s");
  assert.equal(formatDuration(1_122_000), "18m 42s");
  assert.equal(formatDuration(7_500_000), "2h 5m");
  assert.equal(formatDuration(-1), "unknown");
});

test("HTML surfaces reduced capability calmly rather than as an error", () => {
  const html = renderStandaloneHtml(report());
  assert.match(html, /not available on this machine/);
  assert.ok(!/Docker is missing/i.test(html));
});
