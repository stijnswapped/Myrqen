import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import {
  validateFindingSubmission,
  validateReport,
  validateScanEvent,
  validateSharePolicy,
  formatIssues,
  REPORT_SCHEMA,
  FINDING_SCHEMA,
  SCAN_EVENT_SCHEMA
} from "../dist/index.js";

const ROOT = path.resolve(import.meta.dirname, "../../..");

function readSchema(name) {
  return JSON.parse(fs.readFileSync(path.join(ROOT, "schemas", name), "utf8"));
}

test("generated schema module matches schemas/*.json (drift guard)", () => {
  assert.deepEqual(JSON.parse(JSON.stringify(REPORT_SCHEMA)), readSchema("report.schema.json"));
  assert.deepEqual(JSON.parse(JSON.stringify(FINDING_SCHEMA)), readSchema("finding.schema.json"));
  assert.deepEqual(JSON.parse(JSON.stringify(SCAN_EVENT_SCHEMA)), readSchema("scan-event.schema.json"));
});

const goodSubmission = {
  title: "Order ownership is not enforced",
  category: "broken_object_level_authorization",
  severity: "high",
  verification: "verified",
  summary: "The order route loads the record by identifier without scoping to the authenticated subject.",
  impact: "A signed-in user can read another account's order data by changing the identifier.",
  affected: { component: "orders API", route: "GET /api/orders/:id", file: "src/routes/orders.ts" },
  evidence: [{ kind: "identity_differential", description: "User A received User B's fixture order with status 200." }],
  remediation: "Scope the query to the authenticated subject or verify ownership before returning the record.",
  verificationPlan: "Repeat the cross-account request and assert a 403/404 response."
};

test("valid finding submission is accepted", () => {
  const result = validateFindingSubmission(goodSubmission);
  assert.equal(result.valid, true, formatIssues(result.issues));
});

test("unknown submission field is rejected with an actionable message", () => {
  const result = validateFindingSubmission({ ...goodSubmission, exploitPayload: "rm -rf /" });
  assert.equal(result.valid, false);
  assert.match(formatIssues(result.issues), /unexpected field "exploitPayload"/);
});

test("missing required submission field names the field", () => {
  const { remediation, ...rest } = goodSubmission;
  const result = validateFindingSubmission(rest);
  assert.equal(result.valid, false);
  assert.match(formatIssues(result.issues), /missing required field "remediation"/);
});

test("severity and verification are independent enums", () => {
  const result = validateFindingSubmission({ ...goodSubmission, severity: "verified" });
  assert.equal(result.valid, false);
});

test("scan event rejects arbitrary payload fields", () => {
  const base = { eventId: "e1", reportId: "r1", type: "phase_started", occurredAt: new Date().toISOString() };
  assert.equal(validateScanEvent(base).valid, true);
  assert.equal(validateScanEvent({ ...base, sourceCode: "const a = 1" }).valid, false);
  assert.equal(validateScanEvent({ ...base, aggregate: { validatedCount: 2 } }).valid, true);
  assert.equal(validateScanEvent({ ...base, aggregate: { secretValue: "x" } }).valid, false);
});

test("report schema validates a minimal report and rejects extra fields", () => {
  const report = {
    schemaVersion: "1.0.0",
    id: "rpt_1",
    generatedAt: new Date().toISOString(),
    project: { name: "Example", workspaceKind: "personal" },
    scan: {
      effortRequested: "auto",
      effortResolved: "high",
      durationMs: 1000,
      agent: { name: "Claude Code" },
      tokenUsage: { source: "unavailable" },
      scope: { localTargets: ["http://127.0.0.1:4010"], externalTargets: [] }
    },
    summary: {
      findingCount: 0,
      severityCounts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      verificationCounts: { verified: 0, strong_evidence: 0, needs_review: 0 }
    },
    findings: [],
    coverage: ["source review"],
    limitations: ["no isolated runtime"]
  };
  assert.equal(validateReport(report).valid, true, formatIssues(validateReport(report).issues));
  assert.equal(validateReport({ ...report, repositoryArchive: "base64..." }).valid, false);
});

test("share policy schema accepts typed rules only", () => {
  const policy = {
    version: 1,
    sections: { mode: "allow_only", ids: ["summary", "findings"] },
    findings: { mode: "allow_only", ids: ["F1"] },
    fields: { evidence: false }
  };
  assert.equal(validateSharePolicy(policy).valid, true);
  assert.equal(validateSharePolicy({ ...policy, script: "return true" }).valid, false);
});
