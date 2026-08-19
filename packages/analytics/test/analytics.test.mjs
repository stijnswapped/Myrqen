import { test } from "node:test";
import assert from "node:assert/strict";
import { PRODUCT_EVENT_NAMES, assertAnalyticsEventSafe, createEvent, tokenMetrics } from "../dist/index.js";

// Assembled at runtime: a provider-shaped literal in a published repository is
// blocked by GitHub's push protection and by every downstream secret scanner, none of
// which can tell that this one is synthetic.
const STRIPE_LIVE_SHAPE = ["sk", "_", "live", "_", "abcdef1234567890"].join("");

const CANARY = "myrqen-canary-2f8c1a94d7be4c5f9a13";

test("a well-formed scan completion event is accepted", () => {
  const event = createEvent({
    name: "scan_completed",
    client: "cli",
    userId: "0f8f0f2e-0000-4000-8000-000000000001",
    reportId: "0f8f0f2e-0000-4000-8000-000000000002",
    agentName: "Claude Code",
    modelName: "claude-opus-5",
    effortRequested: "auto",
    effortResolved: "high",
    metrics: {
      duration_ms: 1_122_000,
      candidate_count: 9,
      validated_count: 3,
      severity_high: 1,
      verification_verified: 1,
      ...tokenMetrics({ source: "estimated", count: 412_000, estimator: "transcript-v1" }),
      isolated_runtime_available: true,
      external_authorized_target_count: 0
    }
  });
  assert.equal(event.version, 1);
  assert.equal(event.metrics.token_source, "estimated");
});

test("report prose, source, and secrets are rejected rather than sanitized", () => {
  const base = { name: "scan_completed", client: "cli", version: 1, occurredAt: new Date().toISOString(), eventId: "e1" };
  const rejected = [
    { ...base, findingTitle: "Order ownership is not enforced" },
    { ...base, sourceSnippet: "const a = 1" },
    { ...base, secret: CANARY },
    { ...base, evidence: "runtime proof" },
    { ...base, repositoryPath: "/Users/dev/project" },
    { ...base, email: "dev@example.com" },
    { ...base, metrics: { finding_title: "x" } },
    { ...base, metrics: { duration_ms: { nested: true } } }
  ];
  for (const event of rejected) {
    assert.throws(() => assertAnalyticsEventSafe(event), /Forbidden|must be/, JSON.stringify(event).slice(0, 80));
  }
});

test("unknown event names are rejected so the taxonomy stays stable", () => {
  assert.throws(
    () =>
      assertAnalyticsEventSafe({
        eventId: "e1",
        name: "arbitrary_event",
        version: 1,
        occurredAt: new Date().toISOString(),
        client: "cli"
      }),
    /Unknown analytics event name/
  );
});

test("an email address cannot be used as a user identifier", () => {
  assert.throws(
    () =>
      assertAnalyticsEventSafe({
        eventId: "e1",
        name: "account_created",
        version: 1,
        occurredAt: new Date().toISOString(),
        client: "web",
        userId: "dev@example.com"
      }),
    /internal identifier/
  );
});

test("long string metrics are refused so prose cannot be smuggled in", () => {
  assert.throws(
    () =>
      assertAnalyticsEventSafe({
        eventId: "e1",
        name: "scan_completed",
        version: 1,
        occurredAt: new Date().toISOString(),
        client: "cli",
        metrics: { result_code: "x".repeat(500) }
      }),
    /safe string length/
  );
});

test("token metrics never carry a count without provenance", () => {
  assert.deepEqual(tokenMetrics({ source: "unavailable", count: 500 }), { token_source: "unavailable" });
  assert.deepEqual(tokenMetrics({ source: "exact", count: 1000 }), { token_source: "exact", token_count: 1000 });
  assert.deepEqual(tokenMetrics({ source: "estimated", count: 10, estimator: "v1" }), {
    token_source: "estimated",
    token_count: 10,
    token_estimator: "v1"
  });
});

const envelope = (extra) => ({
  eventId: "e1",
  name: "scan_completed",
  version: 1,
  occurredAt: new Date().toISOString(),
  client: "cli",
  ...extra
});

test("dimensions are bounded labels, so prose, paths, emails and secrets cannot ride in on them", () => {
  const rejected = [
    { agentName: "A1 Order records are readable across accounts. Evidence: see the report." },
    { agentName: "x".repeat(200) },
    { modelName: "claude-opus-5 as configured in /Users/dev/private-repo" },
    { osFamily: "darwin /Users/dev/thuis/private-repo" },
    { arch: `arm64 ${STRIPE_LIVE_SHAPE}` },
    { clientVersion: "0.1.0 https://example.test/?token=abc" },
    { agentVersion: "dev@example.com" }
  ];
  for (const dimension of rejected) {
    assert.throws(() => assertAnalyticsEventSafe(envelope(dimension)), /not free text/, JSON.stringify(dimension));
  }
});

test("the dimension values real agents send are still accepted", () => {
  const accepted = [
    { agentName: "Claude Code", agentVersion: "2.0.14", modelName: "claude-opus-5" },
    { agentName: "e2e-harness", modelName: "deterministic-analyzer" },
    { osFamily: "darwin", arch: "arm64", clientVersion: "0.1.0" },
    { osFamily: "win32", arch: "x64", clientVersion: "1.0.0-rc.1" }
  ];
  for (const dimension of accepted) {
    assertAnalyticsEventSafe(envelope(dimension));
  }
});

test("workspace and report attribution must be internal identifiers, not paths or addresses", () => {
  for (const field of ["workspaceId", "projectId", "reportId", "anonymousSessionId"]) {
    assert.throws(() => assertAnalyticsEventSafe(envelope({ [field]: "/Users/dev/private-repo" })), /internal identifier/);
    assert.throws(() => assertAnalyticsEventSafe(envelope({ [field]: "dev@example.com" })), /internal identifier/);
  }
  assertAnalyticsEventSafe(envelope({ workspaceId: "8db9665c-763f-4fb4-adf9-f18b6e351666" }));
});

test("string metrics carry short codes, not sentences", () => {
  assert.throws(
    () => assertAnalyticsEventSafe(envelope({ metrics: { result_code: "SQL injection in /api/login?user=admin" } })),
    /short code/
  );
  assertAnalyticsEventSafe(envelope({ metrics: { result_code: "UPLOAD_FAILED" } }));
});

test("a token count that no real scan could produce is refused rather than shown as exact", () => {
  assert.throws(
    () => assertAnalyticsEventSafe(envelope({ metrics: { token_source: "exact", token_count: 999_999_999 } })),
    /not a plausible scan measurement/
  );
  assert.throws(
    () => assertAnalyticsEventSafe(envelope({ metrics: { token_source: "exact", token_count: 1.5 } })),
    /whole number of tokens/
  );
  assert.throws(
    () => assertAnalyticsEventSafe(envelope({ metrics: { token_count: 1000 } })),
    /must travel with the token_source/
  );
  assert.throws(
    () => assertAnalyticsEventSafe(envelope({ metrics: { token_source: "guessed", token_count: 10 } })),
    /exact, estimated, or unavailable/
  );
  assertAnalyticsEventSafe(envelope({ metrics: { token_source: "exact", token_count: 412_000 } }));
});

test("the taxonomy only declares events that something emits", () => {
  for (const orphan of [
    "marketing_landing_viewed",
    "signup_started",
    "install_command_copied",
    "onboarding_started",
    "project_binding_started",
    "local_report_opened",
    "cloud_report_opened",
    "scan_failed",
    "share_opened",
    "share_denied",
    "agent_installed",
    "agent_detected"
  ]) {
    assert.ok(!PRODUCT_EVENT_NAMES.includes(orphan), `${orphan} has no emitter and must not be declared`);
  }
});
