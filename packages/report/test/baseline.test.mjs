import { test } from "node:test";
import assert from "node:assert/strict";
import {
  BASELINE_SCHEMA,
  baselineFingerprint,
  buildReport,
  compareToBaseline,
  createBaseline,
  parseBaseline,
  renderMarkdown,
  renderSarif,
  renderStandaloneHtml,
  serializeBaseline
} from "../dist/index.js";
import { validateReport } from "../../contracts/dist/index.js";

function finding(overrides = {}) {
  return {
    id: "MYR-001",
    title: "Search query is built from the request",
    category: "unsafe_query_composition",
    severity: "high",
    verification: "strong_evidence",
    summary: "The search handler concatenates the query string into SQL at line 119.",
    impact: "Any caller can read the whole database.",
    affected: { component: "src/server.js", route: "GET /api/products/search", file: "src/server.js", lineStart: 119 },
    evidence: [
      {
        kind: "source",
        description: "Data flow: req.query.q reaches db.query(`SELECT … ${q}`) in the same function with no validating guard between them.",
        location: "src/server.js:119",
        snippet: "const rows = db.query(`SELECT * FROM products WHERE name LIKE '%${q}%'`);"
      }
    ],
    remediation: "Use a parameterized query.",
    verificationPlan: "Send a quote and assert a 400.",
    ...overrides
  };
}

function moved(base, lines) {
  return {
    ...base,
    summary: base.summary.replace(/\d+/, String(119 + lines)),
    affected: { ...base.affected, lineStart: 119 + lines },
    evidence: base.evidence.map((item) => ({ ...item, location: `src/server.js:${119 + lines}` }))
  };
}

test("a fingerprint survives the finding moving down the file", () => {
  const original = finding();
  assert.equal(baselineFingerprint(original), baselineFingerprint(moved(original, 37)));
  assert.equal(baselineFingerprint(original), baselineFingerprint({ ...original, id: "MYR-099", verification: "verified" }));
  assert.match(baselineFingerprint(original), /^bl_[0-9a-f]{32}$/);
});

test("a fingerprint changes when the defect is a different one", () => {
  const original = finding();
  assert.notEqual(baselineFingerprint(original), baselineFingerprint({ ...original, category: "sql_injection" }));
  assert.notEqual(baselineFingerprint(original), baselineFingerprint({ ...original, affected: { ...original.affected, file: "src/other.js" } }));
  assert.notEqual(baselineFingerprint(original), baselineFingerprint({ ...original, affected: { ...original.affected, route: "GET /api/orders" } }));
  const otherSink = {
    ...original,
    evidence: [{ kind: "source", description: "Data flow: req.body.name reaches db.exec(name) in the same function with no validating guard between them." }]
  };
  assert.notEqual(baselineFingerprint(original), baselineFingerprint(otherSink));
});

test("a concrete identifier in the route does not split a finding", () => {
  const a = finding({ affected: { component: "x", route: "GET /api/orders/12", file: "src/a.js" } });
  const b = finding({ affected: { component: "x", route: "GET /api/orders/13", file: "src/a.js" } });
  assert.equal(baselineFingerprint(a), baselineFingerprint(b));
});

test("compare marks findings new or unchanged and lists what has gone", () => {
  const kept = finding();
  const gone = finding({ id: "MYR-002", category: "path_traversal", title: "File download reads any path", evidence: [] });
  const baseline = createBaseline([kept, gone], { now: new Date("2026-10-01T00:00:00Z"), fromReportId: "rpt_old" });
  assert.equal(baseline.schema, BASELINE_SCHEMA);
  assert.equal(baseline.entries.length, 2);

  const fresh = finding({ id: "MYR-003", category: "reflected_cross_site_scripting", title: "Search echoes the query", evidence: [] });
  const comparison = compareToBaseline([{ ...moved(kept, 4), id: "MYR-010" }, fresh], baseline);
  assert.deepEqual(comparison.states, { "MYR-010": "unchanged", "MYR-003": "new" });
  assert.deepEqual(comparison.counts, { new: 1, unchanged: 1, fixed: 1 });
  assert.equal(comparison.fixed[0].category, "path_traversal");
  assert.equal(comparison.fromReportId, "rpt_old");
});

test("a finding fixed and verified since the baseline counts as fixed, not unchanged", () => {
  const baseline = createBaseline([finding()]);
  const comparison = compareToBaseline([finding({ status: "fixed_verified" })], baseline);
  assert.deepEqual(comparison.states, {});
  assert.equal(comparison.counts.fixed, 1);
});

test("the baseline file holds no evidence, no code, and round-trips byte for byte", () => {
  const baseline = createBaseline([finding(), finding({ id: "MYR-002", affected: { component: "a", file: "src/a.js" } })], {
    now: new Date("2026-10-01T00:00:00Z")
  });
  const text = serializeBaseline(baseline);
  assert.doesNotMatch(text, /SELECT|db\.query|snippet|evidence/);
  assert.ok(text.endsWith("\n"));
  assert.equal(serializeBaseline(parseBaseline(JSON.parse(text))), text);
  assert.ok(text.indexOf("src/a.js") < text.indexOf("src/server.js"), "entries are sorted by file for stable diffs");
});

test("a malformed baseline is refused with the reason, never half-read", () => {
  assert.throws(() => parseBaseline(null), /not a JSON object/);
  assert.throws(() => parseBaseline({ schema: "other" }), /schema/);
  assert.throws(() => parseBaseline({ schema: BASELINE_SCHEMA, createdAt: "x", entries: [] }), /createdAt/);
  assert.throws(
    () => parseBaseline({ schema: BASELINE_SCHEMA, createdAt: "2026-10-01T00:00:00Z", entries: [{ fingerprint: "nope" }] }),
    /fingerprint/
  );
});

function report(findings, baseline) {
  return buildReport({
    id: "rpt_new",
    project: { name: "Shop", workspaceKind: "personal" },
    scan: {
      effortRequested: "high",
      effortResolved: "high",
      durationMs: 1000,
      agent: { name: "Claude Code" },
      tokenUsage: { source: "unavailable" },
      scope: { localTargets: [], externalTargets: [] }
    },
    findings,
    coverage: ["Source review"],
    limitations: ["None"],
    ...(baseline ? { baseline } : {})
  });
}

test("a report built against a baseline records the state in every format", () => {
  const known = finding();
  const gone = finding({ id: "MYR-002", category: "path_traversal", title: "File download reads any path", evidence: [] });
  const baseline = createBaseline([known, gone], { now: new Date("2026-10-01T00:00:00Z") });
  const fresh = finding({ id: "MYR-003", category: "reflected_cross_site_scripting", title: "Search echoes the query", evidence: [{ kind: "source", description: "The query is echoed into the page." }] });
  const built = report([moved(known, 2), fresh], baseline);

  assert.equal(validateReport(built).valid, true);
  assert.equal(built.findings.find((item) => item.id === "MYR-001").baselineState, "unchanged");
  assert.equal(built.findings.find((item) => item.id === "MYR-003").baselineState, "new");
  assert.deepEqual(built.baseline.counts, { new: 1, unchanged: 1, fixed: 1 });

  const sarif = JSON.parse(renderSarif(built));
  const states = Object.fromEntries(sarif.runs[0].results.map((result) => [result.properties.findingId, result.baselineState]));
  assert.deepEqual(states, { "MYR-001": "unchanged", "MYR-003": "new" });
  assert.ok(sarif.runs[0].results.every((result) => /^bl_/.test(result.partialFingerprints["myrqenBaseline/v1"])));

  const html = renderStandaloneHtml(built);
  assert.match(html, /id="baseline"/);
  assert.match(html, /data-baseline="new"/);
  assert.match(html, /File download reads any path/);

  const markdown = renderMarkdown(built);
  assert.match(markdown, /## Baseline/);
  assert.match(markdown, /1 new · 1 already in the baseline · 1 fixed since/);
  assert.match(markdown, /- Baseline: new/);
});

test("without a baseline, no format invents a baseline state", () => {
  const built = report([finding()]);
  assert.equal(built.baseline, undefined);
  assert.equal(built.findings[0].baselineState, undefined);
  const sarif = JSON.parse(renderSarif(built));
  assert.equal(sarif.runs[0].results[0].baselineState, undefined);
  assert.doesNotMatch(renderMarkdown(built), /## Baseline/);
  assert.doesNotMatch(renderStandaloneHtml(built), /id="baseline"/);
});
