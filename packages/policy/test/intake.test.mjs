import { test } from "node:test";
import assert from "node:assert/strict";
import { containsSecretLikeMaterial, redactText, computeFingerprint, intakeFinding, normalizeRoute, summarize } from "../dist/index.js";

const CANARY = "myrqen-canary-2f8c1a94d7be4c5f9a13";

function options(knownSecrets = []) {
  let counter = 0;
  return { knownSecrets, nextId: () => `MYR-${String(++counter).padStart(3, "0")}` };
}

const base = {
  title: "Order ownership is not enforced",
  category: "Broken Object Level Authorization",
  severity: "high",
  verification: "verified",
  summary: "The order route loads the record by identifier without scoping it to the authenticated subject.",
  impact: "A signed-in user can read another account's order data by changing the identifier in the path.",
  affected: { component: "orders API", route: "GET /api/orders/12", file: "src/routes/orders.ts" },
  evidence: [{ kind: "identity_differential", description: "User A received User B's fixture order with status 200." }],
  remediation: "Scope the query to the authenticated subject or verify ownership before returning the record.",
  verificationPlan: "Repeat the cross-account request and assert a 403 or 404 response."
};

test("a valid submission is accepted and assigned a CLI-owned id and fingerprint", () => {
  const { findings, result } = intakeFinding([], base, options());
  assert.equal(result.accepted, true);
  assert.equal(result.action, "created");
  assert.equal(result.findingId, "MYR-001");
  assert.equal(findings[0].id, "MYR-001");
  assert.match(findings[0].fingerprint, /^fp_[0-9a-f]{32}$/);
  assert.equal(findings[0].status, "open");
  assert.ok(findings[0].firstSeenAt);
});

test("category is normalized to a stable machine form", () => {
  const { findings } = intakeFinding([], base, options());
  assert.equal(findings[0].category, "broken_object_level_authorization");
});

test("an invalid submission is rejected with an actionable local error", () => {
  const { findings, result } = intakeFinding([], { ...base, evidence: [] }, options());
  assert.equal(result.accepted, false);
  assert.equal(result.action, "rejected");
  assert.equal(findings.length, 0);
  assert.match(result.errors.join(" "), /finding-submission\.schema\.json/);
});

test("an agent-supplied id or extra field is refused rather than trusted", () => {
  const { result } = intakeFinding([], { ...base, id: "attacker-chosen" }, options());
  assert.equal(result.accepted, false);
  assert.match(result.errors.join(" "), /unexpected field "id"/);
});

test("secret values in a finding are redacted before storage", () => {
  const submission = {
    ...base,
    evidence: [
      {
        kind: "source",
        description: `The handler logs the API key ${CANARY} on failure.`,
        snippet: `logger.info("key", "${CANARY}");`
      }
    ]
  };
  const { findings, result } = intakeFinding([], submission, options([CANARY]));
  assert.equal(result.accepted, true);
  assert.ok(result.redactions >= 2);
  const serialized = JSON.stringify(findings[0]);
  assert.ok(!serialized.includes(CANARY));
  assert.match(result.warnings.join(" "), /redacted/);
});

test("duplicate evidence for the same root cause becomes corroboration, not a second finding", () => {
  const opts = options();
  const first = intakeFinding([], base, opts);
  const second = intakeFinding(
    first.findings,
    {
      ...base,
      affected: { ...base.affected, route: "GET /api/orders/98" },
      evidence: [{ kind: "source", description: "The query in orders.ts has no ownership predicate at line 42." }]
    },
    opts
  );
  assert.equal(second.result.action, "merged_as_corroboration");
  assert.equal(second.result.deduplicatedInto, "MYR-001");
  assert.equal(second.findings.length, 1);
  assert.equal(second.findings[0].corroboration.length, 1);
});

test("a genuinely different finding is not merged", () => {
  const opts = options();
  const first = intakeFinding([], base, opts);
  const second = intakeFinding(
    first.findings,
    {
      ...base,
      title: "Server fetch accepts untrusted destination",
      category: "server_side_request_forgery",
      summary: "User-controlled input reaches a server-side fetch call without an allowlist of permitted hosts.",
      affected: { component: "import service", file: "src/server/import.ts" }
    },
    opts
  );
  assert.equal(second.result.action, "created");
  assert.equal(second.findings.length, 2);
});

test("merging can only strengthen severity and verification", () => {
  const opts = options();
  const first = intakeFinding([], { ...base, severity: "medium", verification: "needs_review" }, opts);
  const second = intakeFinding(first.findings, { ...base, severity: "high", verification: "verified" }, opts);
  assert.equal(second.findings[0].severity, "high");
  assert.equal(second.findings[0].verification, "verified");

  const third = intakeFinding(second.findings, { ...base, severity: "low", verification: "needs_review" }, opts);
  assert.equal(third.findings[0].severity, "high", "severity must not be downgraded by a weaker duplicate");
  assert.equal(third.findings[0].verification, "verified");
});

test("critical severity with needs_review verification is capped and explained", () => {
  const { findings, result } = intakeFinding(
    [],
    { ...base, severity: "critical", verification: "needs_review" },
    options()
  );
  assert.equal(findings[0].severity, "high");
  assert.match(result.warnings.join(" "), /needs_review was reduced/);
});

test("commonly over-rated categories are capped without runtime evidence", () => {
  const { findings, result } = intakeFinding(
    [],
    {
      ...base,
      category: "missing_security_header",
      severity: "high",
      evidence: [{ kind: "configuration", description: "No Content-Security-Policy header is configured for the app." }]
    },
    options()
  );
  assert.equal(findings[0].severity, "medium");
  assert.match(result.warnings.join(" "), /reduced to medium/);
});

test("route normalization collapses identifiers", () => {
  assert.equal(normalizeRoute("GET /api/orders/12?x=1"), "get /api/orders/:id");
  assert.equal(
    normalizeRoute("/users/2b1c8ac1-1111-4222-8333-444455556666/orders"),
    "/users/:id/orders"
  );
});

test("fingerprints ignore concrete identifiers but respect category", () => {
  const a = computeFingerprint({ ...base, affected: { ...base.affected, route: "GET /api/orders/1" } });
  const b = computeFingerprint({ ...base, affected: { ...base.affected, route: "GET /api/orders/999" } });
  const c = computeFingerprint({ ...base, category: "different_category" });
  assert.equal(a, b);
  assert.notEqual(a, c);
});

test("summarize counts severity and verification independently", () => {
  const opts = options();
  let findings = [];
  for (const [severity, verification] of [
    ["high", "verified"],
    ["medium", "needs_review"],
    ["medium", "verified"]
  ]) {
    const out = intakeFinding(
      findings,
      { ...base, severity, verification, title: `${severity} ${verification} issue`, category: `cat_${severity}_${verification}`, affected: { component: `component ${severity} ${verification}` } },
      opts
    );
    findings = out.findings;
  }
  const summary = summarize(findings);
  assert.equal(summary.findingCount, 3);
  assert.equal(summary.severityCounts.medium, 2);
  assert.equal(summary.verificationCounts.verified, 2);
  assert.equal(summary.verificationCounts.needs_review, 1);
});

test("a finding that quotes an environment dump is kept, with the value redacted", () => {
  // Redaction used to rewrite `SECRET: value` as `SECRET=[REDACTED]`, which then
  // matched the same pattern again, so the residual check rejected the finding
  // outright. A debug endpoint that dumps the environment is exactly the finding
  // a reader needs, and it was the one guaranteed to disappear.
  const { findings, result } = intakeFinding([], {
    title: "Debug endpoint returns the process environment",
    category: "debug_endpoint_exposure",
    severity: "high",
    verification: "strong_evidence",
    summary: "The route serialises configuration into the response body.",
    impact: "Anyone who can reach the route reads the deployment's configuration.",
    affected: { component: "src/server.js", file: "src/server.js", lineStart: 171, route: "GET /debug/config" },
    evidence: [
      {
        kind: "source",
        description: "The handler writes configuration to the response.",
        snippet: 'return json(response, 200, { env: { PORT, SESSION_SECRET: process.env.SESSION_SECRET } });'
      }
    ],
    remediation: "Remove the route, or require an operator role and return no configuration values.",
    verificationPlan: "Request the route unauthenticated and confirm it is not served."
  }, { knownSecrets: [], nextId: () => "f-1" });

  assert.equal(result.accepted, true, JSON.stringify(result.errors));
  const snippet = findings[0].evidence[0].snippet;
  assert.match(snippet, /SESSION_SECRET: \[REDACTED_SECRET\]/, "the separator is preserved and the value is gone");
});

test("redaction reaches a fixed point", () => {
  const once = redactText("SESSION_SECRET: hunter2hunter2", []);
  assert.equal(containsSecretLikeMaterial(once.value, []), false, "a second pass must find nothing left to redact");
});
