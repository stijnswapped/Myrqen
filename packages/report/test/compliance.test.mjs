import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  OWASP_TOP10_2021,
  OWASP_TOP10_2025,
  aggregateCompliance,
  buildReport,
  complianceFor,
  isMapped,
  mappedCategories,
  renderMarkdown,
  renderSarif,
  renderStandaloneHtml
} from "../dist/index.js";

/**
 * Every category the static engines (JavaScript and Python) can emit, read from its source rather than from a
 * list someone has to remember to update. A rule that starts emitting a new category
 * fails this test until the category has a row in the compliance table.
 */
function scannerCategories() {
  // The Python engine is a separate package whose findings ship through the same report.
  const roots = ["../../scan/src", "../../scan-python/src"].map((relative) =>
    fileURLToPath(new URL(relative, import.meta.url))
  );
  const files = [];
  const walk = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const full = path.join(directory, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (/\.(ts|mts)$/.test(entry.name)) files.push(full);
    }
  };
  for (const root of roots) walk(root);
  const categories = new Set();
  for (const file of files) {
    const source = readFileSync(file, "utf8");
    // `category: "x"` and `category: cond ? "x" : "y"`, on one line.
    for (const line of source.matchAll(/\bcategory:\s*([^,\n}]+)/g)) {
      for (const literal of line[1].matchAll(/"([a-z][a-z0-9_]+)"/g)) categories.add(literal[1]);
    }
  }
  return [...categories].sort();
}

test("every category the scanner can emit has a compliance row", () => {
  const categories = scannerCategories();
  assert.ok(categories.length >= 30, `found only ${categories.length} categories; the source scan is broken`);
  const missing = categories.filter((category) => !isMapped(category));
  assert.deepEqual(missing, [], `unmapped scanner categories: ${missing.join(", ")}`);
});

test("every row is complete and spelled the way the standards spell it", () => {
  for (const category of mappedCategories()) {
    const reference = complianceFor({ category });
    assert.ok(reference.cwe.length > 0, `${category}: CWE`);
    for (const cwe of reference.cwe) assert.match(cwe, /^CWE-\d+$/, category);
    assert.ok(reference.owasp2021.length > 0, `${category}: OWASP 2021`);
    assert.ok(reference.owasp2025.length > 0, `${category}: OWASP 2025`);
    for (const id of reference.owasp2021) assert.ok(OWASP_TOP10_2021[id], `${category}: ${id}`);
    for (const id of reference.owasp2025) assert.ok(OWASP_TOP10_2025[id], `${category}: ${id}`);
    for (const id of reference.asvs) assert.match(id, /^v(4\.0\.3|5\.0\.0)-\d+\.\d+\.\d+$/, `${category}: ${id}`);
  }
});

test("known placements match OWASP's own CWE lists", () => {
  assert.deepEqual(complianceFor({ category: "server_side_request_forgery" }).owasp2025, ["A01:2025"]);
  assert.deepEqual(complianceFor({ category: "server_side_request_forgery" }).owasp2021, ["A10:2021"]);
  assert.deepEqual(complianceFor({ category: "sql_injection" }).owasp2025, ["A05:2025"]);
  assert.deepEqual(complianceFor({ category: "dependency_with_known_advisory" }).owasp2025, ["A03:2025"]);
  assert.deepEqual(complianceFor({ category: "verbose_error_response" }).owasp2025, ["A10:2025"]);
  assert.ok(complianceFor({ category: "sql_injection" }).asvs.includes("v4.0.3-5.3.4"));
  assert.ok(complianceFor({ category: "sql_injection" }).asvs.includes("v5.0.0-1.2.4"));
  assert.deepEqual(complianceFor({ category: "jwt_weak_secret" }).cwe, ["CWE-1391", "CWE-798", "CWE-321"]);
  assert.deepEqual(complianceFor({ category: "jwt_weak_secret" }).owasp2025, ["A04:2025", "A07:2025"]);
});

test("aliases and a finding's own CWE ids are honoured", () => {
  assert.deepEqual(complianceFor({ category: "IDOR" }).owasp2025, ["A01:2025"]);
  const own = complianceFor({ category: "sql_injection", taxonomy: ["CWE-564", "OWASP-A03"] });
  assert.deepEqual(own.cwe, ["CWE-89", "CWE-564"]);
});

test("an unmapped category falls back to its taxonomy, read as the 2021 edition", () => {
  const reference = complianceFor({ category: "something_novel", taxonomy: ["CWE-1", "OWASP-A04"] });
  assert.deepEqual(reference.cwe, ["CWE-1"]);
  assert.deepEqual(reference.owasp2021, ["A04:2021"]);
  assert.deepEqual(reference.owasp2025, []);
  assert.deepEqual(reference.asvs, []);
});

function finding(overrides = {}) {
  return {
    id: "MYR-001",
    title: "Search query is built from the request",
    category: "sql_injection",
    severity: "high",
    verification: "verified",
    summary: "The search handler concatenates the query string into SQL.",
    impact: "Any caller can read the whole database.",
    affected: { component: "search", route: "GET /search", file: "src/search.ts", lineStart: 12 },
    evidence: [{ kind: "source", description: "Concatenation into db.query." }],
    remediation: "Use a parameterized query.",
    verificationPlan: "Send a quote and assert a 400.",
    ...overrides
  };
}

function report(findings) {
  return buildReport({
    id: "rpt_c",
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
    limitations: ["None"]
  });
}

test("the JSON report stores each finding's references", () => {
  const built = report([finding()]);
  assert.deepEqual(built.findings[0].compliance, complianceFor(finding()));
});

test("HTML and Markdown show references per finding and an aggregated section", () => {
  const built = report([finding(), finding({ id: "MYR-002", category: "server_side_request_forgery", title: "Import fetches any URL" })]);
  const html = renderStandaloneHtml(built);
  assert.match(html, /id="compliance"/);
  assert.match(html, /CWE-89/);
  assert.match(html, /A05:2025/);
  assert.match(html, /ASVS 5\.0\.0 1\.2\.4/);
  const markdown = renderMarkdown(built);
  assert.match(markdown, /## Compliance/);
  assert.match(markdown, /\| A01:2025 Broken Access Control \| MYR-002 \|/);
  assert.match(markdown, /Standards: CWE-89/);
});

test("SARIF tags results and rules, links the CWE, and declares the taxonomy", () => {
  const sarif = JSON.parse(renderSarif(report([finding()])));
  const run = sarif.runs[0];
  const rule = run.tool.driver.rules[0];
  assert.equal(rule.helpUri, "https://cwe.mitre.org/data/definitions/89.html");
  assert.ok(rule.properties.tags.includes("external/cwe/cwe-89"));
  assert.ok(rule.properties.tags.includes("owasp-top10-2025/A05"));
  assert.ok(rule.properties.tags.includes("owasp-top10-2021/A03"));
  assert.ok(rule.relationships.some((relation) => relation.target.id === "89" && relation.target.toolComponent.name === "CWE"));
  assert.equal(run.taxonomies[0].name, "CWE");
  assert.ok(run.taxonomies[0].taxa.some((taxon) => taxon.id === "89"));
  assert.ok(run.results[0].properties.tags.includes("external/cwe/cwe-89"));
});

test("the aggregate follows the 2025 order and counts multi-mapped findings under each", () => {
  const rows = aggregateCompliance([
    finding({ id: "A", category: "weak_session_identifier" }),
    finding({ id: "B", category: "sql_injection" }),
    finding({ id: "C", category: "something_novel" })
  ]);
  assert.deepEqual(rows.map((row) => row.id), ["A04:2025", "A05:2025", "A07:2025", "unmapped"]);
  assert.deepEqual(rows.find((row) => row.id === "A07:2025").findingIds, ["A"]);
});
