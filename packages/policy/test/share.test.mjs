import { test } from "node:test";
import assert from "node:assert/strict";
import { describeProjection, projectReport, resolveSharePrincipal } from "../dist/index.js";

const REPORT = {
  schemaVersion: "1.0.0",
  id: "rpt_1",
  generatedAt: "2026-08-18T10:00:00.000Z",
  project: { name: "Checkout API", workspaceKind: "personal", workspaceName: "Personal" },
  scan: {
    effortRequested: "auto",
    effortResolved: "high",
    durationMs: 1_122_000,
    agent: { name: "Claude Code", model: "claude-opus-5" },
    host: { osFamily: "darwin", arch: "arm64" },
    tokenUsage: { source: "estimated", count: 412_000, estimator: "transcript-v1" },
    scope: { localTargets: ["http://127.0.0.1:4010"], externalTargets: [] }
  },
  summary: {
    findingCount: 3,
    severityCounts: { critical: 0, high: 1, medium: 1, low: 1, info: 0 },
    verificationCounts: { verified: 1, strong_evidence: 1, needs_review: 1 }
  },
  findings: [
    finding("F1", "high", "verified", "Order ownership is not enforced"),
    finding("F2", "medium", "strong_evidence", "Server fetch accepts untrusted destination"),
    finding("F3", "low", "needs_review", "Debug response includes stack metadata")
  ],
  coverage: ["source review", "local runtime validation"],
  limitations: ["No isolated runtime available"]
};

function finding(id, severity, verification, title) {
  return {
    id,
    title,
    category: "test_category",
    severity,
    verification,
    summary: `${title} summary`,
    impact: `${title} impact`,
    affected: { component: "orders API", route: "GET /api/orders/:id", file: "src/routes/orders.ts" },
    evidence: [
      { kind: "source", description: `${title} evidence`, snippet: "const order = await db.find(id);" }
    ],
    remediation: `${title} remediation`,
    verificationPlan: `${title} verification plan`,
    reproduction: `${title} reproduction steps`
  };
}

const allowOnly = (ids, fields = {}) => ({
  version: 1,
  sections: { mode: "allow_only", ids: ["summary", "findings"] },
  findings: { mode: "allow_only", ids },
  fields
});

test("two principals on the same share receive structurally different payloads", () => {
  const alice = projectReport(REPORT, allowOnly(["F1", "F2"], { evidence: false, code: false }), {
    principalType: "email",
    label: "alice@example.com"
  });
  const bob = projectReport(REPORT, allowOnly(["F2", "F3"]), { principalType: "email", label: "bob@example.com" });

  assert.deepEqual(alice.findings.map((f) => f.id), ["F1", "F2"]);
  assert.deepEqual(bob.findings.map((f) => f.id), ["F2", "F3"]);

  const aliceJson = JSON.stringify(alice);
  const bobJson = JSON.stringify(bob);
  assert.ok(!aliceJson.includes("F3"), "Alice payload must not contain F3 at all");
  assert.ok(!bobJson.includes("F1"), "Bob payload must not contain F1 at all");
  assert.ok(!aliceJson.includes("const order = await db.find(id);"), "hidden code must be absent, not hidden");
});

test("hidden sections are absent from the projection, not merely flagged", () => {
  const projection = projectReport(REPORT, allowOnly(["F1"]), { principalType: "user" });
  assert.equal(projection.coverage, undefined);
  assert.equal(projection.limitations, undefined);
  assert.equal(projection.scan, undefined);
  assert.ok(!JSON.stringify(projection).includes("claude-opus-5"));
});

test("summary counts are recomputed for the projected finding set", () => {
  const projection = projectReport(REPORT, allowOnly(["F3"]), { principalType: "user" });
  assert.equal(projection.summary.findingCount, 1);
  assert.equal(projection.summary.severityCounts.high, 0);
  assert.equal(projection.summary.severityCounts.low, 1);
  assert.equal(projection.summary.verificationCounts.verified, 0);
});

test("field masks remove remediation and reproduction content", () => {
  const projection = projectReport(
    REPORT,
    { ...allowOnly(["F1"]), fields: { remediation: false, reproduction: false } },
    { principalType: "user" }
  );
  const json = JSON.stringify(projection);
  assert.ok(!json.includes("Order ownership is not enforced remediation"));
  assert.ok(!json.includes("reproduction steps"));
  assert.match(projection.findings[0].remediation, /not shared with this viewer/);
});

test("maxSeverity filters out findings above the permitted band", () => {
  const policy = {
    version: 1,
    sections: { mode: "allow_all", ids: [] },
    findings: { mode: "allow_all", ids: [], maxSeverity: "medium" },
    fields: {}
  };
  const projection = projectReport(REPORT, policy, { principalType: "user" });
  assert.deepEqual(projection.findings.map((f) => f.id), ["F2", "F3"]);
});

test("anonymized view withholds component names, code, and scope", () => {
  const policy = {
    version: 1,
    sections: { mode: "allow_all", ids: [] },
    findings: { mode: "allow_all", ids: [] },
    fields: {},
    anonymize: true
  };
  const projection = projectReport(REPORT, policy, { principalType: "anonymous" });
  const json = JSON.stringify(projection);
  assert.ok(!json.includes("src/routes/orders.ts"));
  assert.ok(!json.includes("const order = await db.find(id);"));
  assert.ok(!json.includes("127.0.0.1"));
  assert.equal(projection.project.name, "Redacted project");
  assert.match(projection.redactionNotice, /anonymized/i);
});

const share = (overrides = {}) => ({
  mode: "account_allowlist",
  anonymousAllowed: false,
  hasPassword: false,
  defaultPolicy: allowOnly([]),
  principals: [],
  ...overrides
});

test("owner always receives the full report", () => {
  const resolution = resolveSharePrincipal(share(), { anonymous: false, userId: "u1" }, { isOwner: true });
  assert.equal(resolution.outcome, "allowed");
  assert.equal(resolution.policy.sections.mode, "allow_all");
});

test("an account with no matching rule receives no content", () => {
  const resolution = resolveSharePrincipal(
    share({ principals: [{ id: "p1", principalType: "email", principalValue: "alice@example.com", policy: allowOnly(["F1"]) }] }),
    { anonymous: false, userId: "u9", email: "carol@example.com" }
  );
  assert.equal(resolution.outcome, "denied");
  assert.equal(resolution.reason, "not_permitted");
});

test("anonymous viewers are asked to authenticate unless anonymous access is explicit", () => {
  assert.equal(resolveSharePrincipal(share({ mode: "unlisted" }), { anonymous: true }).reason, "authentication_required");
  const open = resolveSharePrincipal(share({ mode: "anyone_with_link", anonymousAllowed: true }), { anonymous: true });
  assert.equal(open.outcome, "allowed");
  assert.equal(open.principalType, "anonymous");
});

test("email matching is case and whitespace insensitive", () => {
  const resolution = resolveSharePrincipal(
    share({ principals: [{ id: "p1", principalType: "email", principalValue: "Alice@Example.com ", policy: allowOnly(["F1"]) }] }),
    { anonymous: false, userId: "u2", email: "alice@example.com" }
  );
  assert.equal(resolution.outcome, "allowed");
  assert.deepEqual(resolution.policy.findings.ids, ["F1"]);
});

test("a specific user rule wins over a broader workspace rule", () => {
  const resolution = resolveSharePrincipal(
    share({
      mode: "workspace",
      principals: [
        { id: "p1", principalType: "workspace", principalValue: "w1", policy: allowOnly(["F1", "F2", "F3"]) },
        { id: "p2", principalType: "user", principalValue: "u1", policy: allowOnly(["F1"]) }
      ]
    }),
    { anonymous: false, userId: "u1", workspaceIds: ["w1"] }
  );
  assert.deepEqual(resolution.policy.findings.ids, ["F1"]);
});

test("workspace mode requires membership of the report workspace", () => {
  const member = resolveSharePrincipal(share({ mode: "workspace" }), { anonymous: false, userId: "u1", workspaceIds: ["w1"] }, { reportWorkspaceId: "w1" });
  assert.equal(member.outcome, "allowed");
  const outsider = resolveSharePrincipal(share({ mode: "workspace" }), { anonymous: false, userId: "u2", workspaceIds: ["w9"] }, { reportWorkspaceId: "w1" });
  assert.equal(outsider.outcome, "denied");
});

test("password, expiry, and revocation gate before any projection", () => {
  const now = new Date("2026-08-18T12:00:00Z");
  const locked = resolveSharePrincipal(share({ mode: "anyone_with_link", hasPassword: true, anonymousAllowed: true }), { anonymous: true }, { now });
  assert.equal(locked.outcome, "password_required");

  const unlocked = resolveSharePrincipal(
    share({ mode: "anyone_with_link", hasPassword: true, anonymousAllowed: true }),
    { anonymous: true },
    { now, passwordVerified: true }
  );
  assert.equal(unlocked.outcome, "allowed");

  const expired = resolveSharePrincipal(
    share({ mode: "anyone_with_link", anonymousAllowed: true, expiresAt: "2026-08-18T11:00:00Z" }),
    { anonymous: true },
    { now }
  );
  assert.equal(expired.reason, "expired");

  const revoked = resolveSharePrincipal(
    share({ mode: "anyone_with_link", anonymousAllowed: true, revokedAt: "2026-08-18T11:00:00Z" }),
    { anonymous: true },
    { now }
  );
  assert.equal(revoked.reason, "revoked");
});

test("revocation is checked even for the owner path input order", () => {
  const revoked = resolveSharePrincipal(share({ revokedAt: "2026-01-01T00:00:00Z" }), { anonymous: false, userId: "u1" }, { isOwner: true });
  assert.equal(revoked.outcome, "denied");
});

test("projection preview describes exactly what a principal receives", () => {
  const lines = describeProjection(allowOnly(["F1", "F2"], { evidence: false }), 3);
  assert.match(lines.join(" "), /Findings: 2 of 3/);
  assert.match(lines.join(" "), /Hidden fields: evidence/);
});

test("a projection keeps a finding's baseline state unless metadata is withheld", () => {
  const report = { ...REPORT, findings: REPORT.findings.map((item) => ({ ...item, baselineState: "new" })) };
  const shared = projectReport(report, allowOnly(["F1"]), { principalType: "email", label: "a@example.com" });
  assert.equal(shared.findings[0].baselineState, "new");
  const bare = projectReport(report, allowOnly(["F1"], { metadata: false }), { principalType: "email", label: "a@example.com" });
  assert.equal(bare.findings[0].baselineState, undefined);
});
