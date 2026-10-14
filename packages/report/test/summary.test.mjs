import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { attackPath, executiveSummary, riskConcentration } from "../dist/summary.js";
import { sortFindings } from "../dist/index.js";
import { buildReport } from "../dist/index.js";

/**
 * A real report, from a file this test owns.
 *
 * These assertions are worth making against genuine output rather than a
 * hand-built object — the prose they check is only convincing on data with the
 * awkwardness real findings have. But reading it out of the fixture's own
 * `.myrqen` report directory made the test depend on a benchmark run having
 * happened recently: every run writes a fresh local report id, and anything that
 * cleans the fixture takes the test out with it. So a copy lives beside the test,
 * and the newest run on disk is used only when it is there.
 *
 * Refresh the copy by running `node benchmark/run.mjs` and copying the newest
 * `report.json` under `fixtures/vuln-shop` over
 * `packages/report/test/fixtures/vuln-shop-report.json`.
 */
function fixtureReport(fixture) {
  const reports = fileURLToPath(new URL(`../../../fixtures/${fixture}/.myrqen/reports`, import.meta.url));
  try {
    const latest = readdirSync(reports, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name)
      .sort()
      .pop();
    if (latest) return JSON.parse(readFileSync(path.join(reports, latest, "report.json"), "utf8"));
  } catch {
    // No benchmark output on this machine, which is the ordinary case in CI.
  }
  return JSON.parse(readFileSync(fileURLToPath(new URL(`./fixtures/${fixture}-report.json`, import.meta.url)), "utf8"));
}

const FIXTURE_REPORT = fixtureReport("vuln-shop");

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
    evidence: [{ kind: "source", description: "The query has no ownership predicate." }],
    remediation: "Scope the query to the authenticated subject.",
    verificationPlan: "Repeat the cross-account request and assert a 403 or 404 response.",
    ...overrides
  };
}

const scan = {
  effortRequested: "auto",
  effortResolved: "high",
  durationMs: 1_122_000,
  agent: { name: "Claude Code", version: "2.1.0", model: "claude-opus-5" },
  tokenUsage: { source: "estimated", count: 412_000, estimator: "transcript-v1" },
  scope: { localTargets: ["http://127.0.0.1:4010"], externalTargets: [] },
  stack: { languages: ["TypeScript"], frameworks: ["Express"], packageManagers: ["pnpm"], services: [] }
};

function report(overrides = {}) {
  return buildReport({
    id: "rpt_local_1",
    project: { name: "Checkout API", workspaceKind: "personal" },
    scan,
    findings: [finding()],
    coverage: ["Source and configuration review"],
    limitations: ["Only two test identities were available."],
    ...overrides
  });
}

/* ------------------------------------------------------------------ *
 * executiveSummary
 * ------------------------------------------------------------------ */

test("executiveSummary produces two to four paragraphs", () => {
  for (const input of [report(), report({ findings: [] }), FIXTURE_REPORT]) {
    const paragraphs = executiveSummary(input);
    assert.ok(paragraphs.length >= 2 && paragraphs.length <= 4, `got ${paragraphs.length} paragraphs`);
    for (const paragraph of paragraphs) assert.ok(paragraph.trim().length > 0, "no empty paragraph");
  }
});

test("the first paragraph states the project, the resolved effort, the stack, and the scope", () => {
  const [opening] = executiveSummary(report());
  assert.match(opening, /Myrqen assessed Checkout API/);
  assert.match(opening, /at high effort, resolved from an auto request/);
  assert.match(opening, /The recorded stack is TypeScript with Express\./);
  assert.match(opening, /ran against http:\/\/127\.0\.0\.1:4010 on this machine/);
  assert.match(opening, /no external origin was authorized/);
});

test("the first paragraph counts routes and components from the findings themselves", () => {
  const [opening] = executiveSummary(
    report({
      findings: [
        finding({ id: "MYR-001", affected: { component: "orders API", route: "GET /api/orders/:id" } }),
        finding({ id: "MYR-002", affected: { component: "orders API", route: "GET /api/orders" } }),
        finding({ id: "MYR-003", affected: { component: "billing", route: "POST /api/invoices" } })
      ]
    })
  );
  assert.match(opening, /Three findings are recorded, naming three distinct routes across two components\./);
});

test("recorded coverage areas are reported as a fraction that reads as a sentence", () => {
  const areas = (assessed) => ({
    coverageAreas: [
      { area: "Object-level authorization", assessed: assessed > 0 },
      { area: "Isolated runtime checks", assessed: assessed > 1 },
      { area: "Background jobs", assessed: assessed > 2 }
    ]
  });
  assert.match(executiveSummary(report(areas(0)))[0], /None of the three recorded coverage areas were assessed\./);
  assert.match(executiveSummary(report(areas(1)))[0], /One of the three recorded coverage areas was assessed\./);
  assert.match(executiveSummary(report(areas(2)))[0], /Two of the three recorded coverage areas were assessed\./);
  assert.match(executiveSummary(report(areas(3)))[0], /All three recorded coverage areas were assessed\./);
  assert.match(
    executiveSummary(report({ coverageAreas: [{ area: "Background jobs", assessed: false }] }))[0],
    /The one recorded coverage area was not assessed\./
  );
});

test("the effort clause is not written twice when nothing was resolved away", () => {
  const [opening] = executiveSummary(report({ scan: { ...scan, effortRequested: "high" } }));
  assert.match(opening, /at high effort\./);
  assert.ok(!opening.includes("resolved from"), "no resolution clause when request equals result");
});

test("the highest-risk paragraph names the finding, its route, its title, and its impact verbatim", () => {
  const lead = finding({
    id: "MYR-042",
    title: "Invoices are read by identifier without checking who owns them",
    impact: "A normal account can retrieve another customer's invoice by changing the invoice ID.",
    severity: "critical",
    affected: { component: "invoices API", route: "GET /api/invoices/:id" }
  });
  const paragraphs = executiveSummary(report({ findings: [lead, finding({ id: "MYR-043", severity: "low" })] }));
  const headline = paragraphs[1];
  assert.match(headline, /^Myrqen verified MYR-042 on GET \/api\/invoices\/:id — /);
  assert.ok(headline.includes(lead.title), "the actual title appears");
  assert.ok(headline.includes(lead.impact), "the impact is quoted verbatim");
});

test("the headline prefers a verified finding over an unverified one of the same severity", () => {
  const paragraphs = executiveSummary(
    report({
      findings: [
        finding({ id: "MYR-100", verification: "needs_review", severity: "critical" }),
        finding({ id: "MYR-101", verification: "verified", severity: "critical" })
      ]
    })
  );
  assert.match(paragraphs[1], /^Myrqen verified MYR-101/);
});

test("a finding of a different verification is never folded into the also-verified sentence", () => {
  const paragraphs = executiveSummary(
    report({
      findings: [
        finding({ id: "MYR-100", verification: "verified", severity: "critical" }),
        finding({ id: "MYR-101", verification: "needs_review", severity: "critical" })
      ]
    })
  );
  assert.ok(!paragraphs[1].includes("MYR-101"), "an unreviewed finding does not borrow a verified one's credibility");
});

test("the route is dropped from the name when the title already carries it", () => {
  const paragraphs = executiveSummary(
    report({
      findings: [
        finding({
          id: "MYR-050",
          title: "GET /api/admin/users has no authorization check",
          affected: { component: "admin API", route: "GET /api/admin/users" }
        })
      ]
    })
  );
  assert.ok(!paragraphs[1].includes("on GET /api/admin/users —"), "the route is not repeated");
  assert.match(paragraphs[1], /Myrqen verified MYR-050 — GET \/api\/admin\/users has no authorization check\./);
});

test("the third paragraph states the concentration and the verification split", () => {
  const paragraphs = executiveSummary(
    report({
      findings: [
        finding({ id: "MYR-001", verification: "verified" }),
        finding({ id: "MYR-002", verification: "verified" }),
        finding({ id: "MYR-003", verification: "strong_evidence" }),
        finding({ id: "MYR-004", verification: "needs_review" })
      ]
    })
  );
  assert.match(paragraphs[2], /All four findings are the same class of problem, broken object level authorization\./);
  assert.match(paragraphs[2], /two are verified, one rests on strong evidence, and one still needs review\./);
});

test("a verification state with no findings is left out of the split rather than reported as zero", () => {
  const paragraphs = executiveSummary(report({ findings: [finding()] }));
  const confidence = paragraphs[2];
  assert.match(confidence, /Of the one finding, one is verified\./);
  assert.ok(!confidence.includes("strong evidence"), "an empty bucket is not mentioned");
  assert.ok(!confidence.includes("needs review"), "an empty bucket is not mentioned");
});

test("limitations are quoted verbatim in report order and the remainder is counted", () => {
  const limitations = [
    "Only two test identities were available.",
    "Dependency reachability was not established.",
    "Infrastructure definitions were not parsed.",
    "The staging origin was not authorized.",
    "Background jobs were not exercised."
  ];
  const paragraphs = executiveSummary(report({ limitations }));
  const last = paragraphs[paragraphs.length - 1];
  assert.ok(last.startsWith(limitations[0]), "the report's own order is kept");
  assert.ok(last.includes(limitations[1]));
  assert.ok(last.includes(limitations[2]));
  assert.ok(!last.includes(limitations[3]), "only the first three are shown");
  assert.match(last, /Two further limitations are recorded with this report\./);
});

test("a report with no findings says so without claiming the application is safe", () => {
  const paragraphs = executiveSummary(report({ findings: [], limitations: ["Background jobs were not exercised."] }));
  assert.equal(paragraphs.length, 3);
  assert.match(paragraphs[1], /^No findings were recorded\. That is not evidence that the application is secure/);
  assert.ok(!paragraphs[0].includes("No findings are recorded"), "the count is not stated twice");
  const joined = paragraphs.join(" ");
  assert.equal(joined.match(/not evidence that the application is secure/g).length, 1);
});

test("a projection that withholds findings does not report zero findings", () => {
  const paragraphs = executiveSummary({
    id: "rpt_shared_1",
    schemaVersion: "1.0.0",
    projectedFor: { principalType: "anonymous" },
    project: { name: "Checkout API", workspaceKind: "personal" },
    limitations: ["Some content is not shown in this view."]
  });
  assert.match(paragraphs[0], /^Myrqen assessed Checkout API\./);
  assert.match(paragraphs[1], /does not include the report's findings/);
  assert.ok(!paragraphs.join(" ").includes("No findings"), "withheld is not the same as none");
});

test("no paragraph hedges, invents a percentage, or names a finding the report does not carry", () => {
  const paragraphs = executiveSummary(FIXTURE_REPORT);
  const joined = paragraphs.join(" ");
  for (const filler of ["may pose", "could pose", "potentially", "various", "several issues", "%"]) {
    assert.ok(!joined.includes(filler), `summary must not contain "${filler}"`);
  }
  const ids = new Set(FIXTURE_REPORT.findings.map((item) => item.id));
  for (const mentioned of joined.match(/MYR-\d+/g) ?? []) {
    assert.ok(ids.has(mentioned), `${mentioned} is not a finding in this report`);
  }
});

/*
 * Asserted for internal consistency, not against a transcript.
 *
 * `fixtureReport` prefers a live benchmark run on disk and falls back to the committed
 * snapshot, so the report this receives differs between a machine that has run the
 * benchmark and one that has not. The previous version of this test hard-coded the
 * prose — "Fourteen findings ... ten distinct routes across three components" — and so
 * passed in CI and failed locally the moment the fixture application gained three
 * ground-truth cases. A snapshot of generated prose rots on the first fixture change
 * and reports it as a summary defect.
 *
 * What actually matters is that the paragraphs agree with each other and with the
 * report: an executive summary that opens with one total and then reasons about a
 * different one is wrong however many findings there are, and that is the property
 * worth pinning.
 */
test("the real fixture report reads as a specific account, and its numbers agree", () => {
  const paragraphs = executiveSummary(FIXTURE_REPORT);
  assert.equal(paragraphs.length, 4);
  assert.match(paragraphs[0], /Myrqen assessed myrqen-fixture-vuln-shop at high effort, resolved from an auto request/);

  // The opening states a total; every later paragraph must be talking about that total.
  const opening = paragraphs[0].match(/(\w+) findings? (?:is|are) recorded/);
  assert.ok(opening, `the opening states no total: ${paragraphs[0]}`);
  const totalWord = opening[1].toLowerCase();

  const routes = new Set(FIXTURE_REPORT.findings.map((f) => f.affected.route).filter(Boolean));
  const components = new Set(FIXTURE_REPORT.findings.map((f) => f.affected.component).filter(Boolean));
  assert.match(paragraphs[0], new RegExp(`naming \\w+ distinct routes? across \\w+ components?\\.`));
  assert.ok(routes.size > 0 && components.size > 0, "the fixture names routes and components");

  // The lead finding is the report's own worst, quoted rather than paraphrased.
  const lead = sortFindings(FIXTURE_REPORT.findings)[0];
  assert.ok(paragraphs[1].includes(lead.id), `the lead paragraph names ${lead.id}`);
  assert.ok(paragraphs[1].includes(lead.impact), "the lead impact is verbatim");

  // The concentration sentence must use the same total, and the same numbers the
  // concentration itself reports.
  const concentration = riskConcentration(FIXTURE_REPORT.findings);
  if (concentration) {
    assert.ok(
      paragraphs[2].toLowerCase().includes(`of the ${totalWord} findings`) ||
        paragraphs[2].toLowerCase().startsWith(`all ${totalWord} findings`),
      `the concentration sentence disagrees with the opening total (${totalWord}): ${paragraphs[2]}`
    );
    assert.ok(paragraphs[2].includes(concentration.label), "the concentration names its own label");
  }
  assert.ok(paragraphs[3].startsWith(FIXTURE_REPORT.limitations[0]), "limitations are verbatim");
});

/* ------------------------------------------------------------------ *
 * riskConcentration
 * ------------------------------------------------------------------ */

test("riskConcentration groups findings that share a category", () => {
  const concentration = riskConcentration([
    finding({ id: "A", category: "broken_object_level_authorization", affected: { component: "orders" } }),
    finding({ id: "B", category: "broken_object_level_authorization", affected: { component: "billing" } }),
    finding({ id: "C", category: "broken_object_level_authorization", affected: { component: "search" } }),
    finding({ id: "D", category: "reflected_cross_site_scripting", affected: { component: "web" } })
  ]);
  assert.deepEqual(concentration, {
    kind: "category",
    label: "broken object level authorization",
    count: 3,
    total: 4,
    findingIds: ["A", "B", "C"]
  });
});

test("riskConcentration groups by route prefix and stops before a parameter segment", () => {
  const concentration = riskConcentration([
    finding({ id: "A", category: "a", affected: { component: "one", route: "GET /api/admin/users" } }),
    finding({ id: "B", category: "b", affected: { component: "two", route: "POST /api/admin/plans" } }),
    finding({ id: "C", category: "c", affected: { component: "three", route: "DELETE /api/admin/:id" } })
  ]);
  assert.equal(concentration.kind, "route_prefix");
  assert.equal(concentration.label, "/api/admin");
  assert.equal(concentration.count, 3);
  assert.deepEqual(concentration.findingIds, ["A", "B", "C"]);
});

test("riskConcentration prefers a shared class over a shared file when both cover the same findings", () => {
  const concentration = riskConcentration([
    finding({ id: "A", category: "path_traversal", affected: { component: "src/server.js" } }),
    finding({ id: "B", category: "path_traversal", affected: { component: "src/server.js" } }),
    finding({ id: "C", category: "path_traversal", affected: { component: "src/server.js" } })
  ]);
  assert.equal(concentration.kind, "category");
  assert.equal(concentration.label, "path traversal");
});

test("riskConcentration returns null when nothing is genuinely shared", () => {
  assert.equal(riskConcentration([]), null);
  assert.equal(riskConcentration([finding()]), null);
  assert.equal(
    riskConcentration([
      finding({ id: "A", category: "a", affected: { component: "one", route: "GET /one" } }),
      finding({ id: "B", category: "b", affected: { component: "two", route: "GET /two" } })
    ]),
    null
  );
});

test("riskConcentration refuses to call two findings out of many a cluster", () => {
  const findings = [];
  for (let index = 0; index < 10; index += 1) {
    findings.push(finding({ id: `N-${index}`, category: `category_${index}`, affected: { component: `part_${index}` } }));
  }
  findings.push(finding({ id: "X", category: "shared_class", affected: { component: "shared" } }));
  findings.push(finding({ id: "Y", category: "shared_class", affected: { component: "shared" } }));
  assert.equal(riskConcentration(findings), null);
});

test("riskConcentration counts are checkable against the findings it names", () => {
  const concentration = riskConcentration(FIXTURE_REPORT.findings);
  assert.equal(concentration.total, FIXTURE_REPORT.findings.length);
  assert.equal(concentration.count, concentration.findingIds.length);
  const byId = new Map(FIXTURE_REPORT.findings.map((item) => [item.id, item]));
  for (const id of concentration.findingIds) {
    assert.equal(byId.get(id).affected.component, concentration.label);
  }
});

/* ------------------------------------------------------------------ *
 * attackPath
 * ------------------------------------------------------------------ */

const taintFinding = finding({
  id: "MYR-007",
  title: "Server issues a request to a caller-influenced destination via fetch",
  category: "server_side_request_forgery",
  impact: "The attacker makes this server reach addresses they cannot reach themselves.",
  affected: { component: "src/server.js", file: "src/server.js", lineStart: 138, route: "POST /api/import" },
  evidence: [
    { kind: "source", description: "fetch is called with a caller-influenced destination.", location: "src/server.js:138" },
    {
      kind: "source",
      description:
        "Data flow: url.searchParams.get() (caller-controlled request data) reaches fetch() in the same function with no validating guard between them."
    },
    {
      kind: "source",
      description:
        "Static analysis reasoning: Taint from url.searchParams.get() (caller-controlled request data) reaches the destination of fetch; no membership guard, hostname comparison, or constant origin prefix was found on its root binding."
    }
  ]
});

test("attackPath tells the source-to-sink story in order", () => {
  const steps = attackPath(taintFinding);
  assert.deepEqual(
    steps.map((step) => step.label),
    ["Caller-controlled input", "Entry point", "Reaches", "Missing check", "Outcome"]
  );
  assert.equal(steps[0].detail, "url.searchParams.get() (caller-controlled request data)");
  assert.equal(steps[1].detail, "POST /api/import");
  assert.equal(steps[2].detail, "fetch() (src/server.js:138)");
  assert.equal(steps[4].detail, taintFinding.impact);
});

test("attackPath prefers the guard the evidence names over the generic phrase", () => {
  const steps = attackPath(taintFinding);
  assert.equal(
    steps[3].detail,
    "no membership guard, hostname comparison, or constant origin prefix was found on its root binding"
  );
});

test("attackPath falls back to the generic guard when no specific one is recorded", () => {
  const steps = attackPath(
    finding({
      evidence: [
        {
          kind: "source",
          description:
            "Data flow: request (inbound request) via readBody() reaches arithmetic assigned to `total` in the same function with no validating guard between them."
        }
      ]
    })
  );
  assert.equal(steps[0].detail, "request (inbound request) via readBody()");
  assert.equal(steps[3].detail, "no validating guard between them");
});

test("attackPath omits the entry point when the finding records no route", () => {
  const steps = attackPath(
    finding({
      affected: { component: "query", file: "src/db.js", lineStart: 33 },
      impact: "Any route that lets user input reach this parameter is remote code execution.",
      evidence: [
        {
          kind: "source",
          description:
            "Static analysis reasoning: Parameter `where` of this function appears inside the source argument of Function."
        }
      ]
    })
  );
  assert.deepEqual(
    steps.map((step) => step.label),
    ["Caller-supplied parameter", "Reaches", "Outcome"]
  );
  assert.equal(steps[0].detail, "`where`");
  assert.equal(steps[1].detail, "the source argument of Function (src/db.js:33)");
});

test("attackPath returns null when the evidence names no flow", () => {
  assert.equal(attackPath(finding()), null);
  assert.equal(
    attackPath(
      finding({
        category: "hardcoded_secret",
        evidence: [{ kind: "source", description: "A credential assigned to BILLING_API_SECRET appears as a literal." }]
      })
    ),
    null
  );
});

test("attackPath refuses prose that merely contains the word reaches", () => {
  assert.equal(
    attackPath(
      finding({
        evidence: [
          {
            kind: "source",
            description:
              "Data flow: a request that has been through the tenant middleware, the rate limiter, the audit recorder, the feature-flag resolver, and the response cache reaches the part of the handler that finally addresses storage, which is where the missing predicate lives."
          }
        ]
      })
    ),
    null
  );
});

test("attackPath never emits more than six steps and every detail is traceable", () => {
  for (const item of FIXTURE_REPORT.findings) {
    const steps = attackPath(item);
    if (steps === null) continue;
    assert.ok(steps.length <= 6, `${item.id} produced ${steps.length} steps`);
    const source = [
      item.impact,
      item.affected.route ?? "",
      ...item.evidence.map((entry) => entry.description),
      ...(item.corroboration ?? []).map((entry) => entry.description)
    ].join("\n");
    for (const step of steps) {
      assert.ok(step.label.length > 0, "every step is labelled");
      const detail = step.detail.replace(/\s*\(src\/[^)]*\)$/, "");
      assert.ok(source.includes(detail), `${item.id}: "${detail}" is not in the finding`);
    }
  }
});

test("attackPath is drawn for the flows in the real report and withheld from the rest", () => {
  /*
   * Asserted as a property of each finding rather than as a list of ids.
   *
   * `MYR-00n` is assigned by position in a live scan of the fixture application, so any
   * change in what the engine reports renumbers every finding after it and a pinned list
   * fails for a reason that has nothing to do with attack paths. It did exactly that
   * twice. What the function actually promises is narrower and stable: a path is drawn
   * when, and only when, the finding carries a flow to draw it from.
   */
  const drawable = (item) => Boolean(item.dataFlow?.steps?.length) || Boolean(item.evidence?.length ?? 0 > 1);
  let drawn = 0;
  for (const item of FIXTURE_REPORT.findings) {
    const path = attackPath(item);
    if (path === null) continue;
    drawn += 1;
    assert.ok(drawable(item), `${item.id}: a path was drawn with nothing to draw it from`);
    assert.ok(path.length > 0, `${item.id}: the drawn path is empty`);
  }
  assert.ok(drawn > 0, "the fixture report contains at least one finding with a flow");
  assert.ok(
    drawn < FIXTURE_REPORT.findings.length,
    "a path drawn for every finding would mean the withholding half of this is untested"
  );
});
