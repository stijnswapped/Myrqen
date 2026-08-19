import { test } from "node:test";
import assert from "node:assert/strict";
import { EFFORT_PROFILES, assertEffortDoesNotWeakenSafety, resolveEffort } from "../dist/index.js";

const minimal = {
  sourceFileCount: 12,
  sourceByteCount: 20_000,
  routeCount: 3,
  hasAuthentication: false,
  hasRoles: false,
  hasDatabaseAccess: false,
  hasFileUpload: false,
  hasServerSideFetch: false,
  hasPaymentIntegration: false,
  runtimeReachable: true,
  testIdentityCount: 2,
  externalTargetCount: 0,
  isolatedRuntimeAvailable: true
};

test("all five effort modes exist and every profile terminates", () => {
  for (const mode of ["low", "high", "xhigh", "ultra"]) {
    const profile = EFFORT_PROFILES[mode];
    assert.ok(profile, `${mode} profile must exist`);
    assert.ok(profile.wallClockBudgetMs > 0, "ultra must still terminate");
    assertEffortDoesNotWeakenSafety(profile);
  }
});

test("effort depth increases monotonically", () => {
  const order = ["low", "high", "xhigh", "ultra"];
  for (let i = 1; i < order.length; i += 1) {
    const previous = EFFORT_PROFILES[order[i - 1]];
    const current = EFFORT_PROFILES[order[i]];
    assert.ok(current.reasoningPasses >= previous.reasoningPasses);
    assert.ok(current.validationPasses >= previous.validationPasses);
    assert.ok(current.wallClockBudgetMs > previous.wallClockBudgetMs);
  }
});

test("an explicit effort is honoured and recorded", () => {
  const resolution = resolveEffort("xhigh", minimal);
  assert.equal(resolution.requested, "xhigh");
  assert.equal(resolution.resolved, "xhigh");
  assert.match(resolution.rationale.join(" "), /Explicit effort/);
});

test("auto resolves low for a tiny static project", () => {
  const resolution = resolveEffort("auto", minimal);
  assert.equal(resolution.requested, "auto");
  assert.equal(resolution.resolved, "low");
  assert.match(resolution.rationale[0], /auto resolved to "low"/);
});

test("auto resolves higher for an authenticated multi-role application", () => {
  const resolution = resolveEffort("auto", {
    ...minimal,
    sourceFileCount: 400,
    routeCount: 30,
    hasAuthentication: true,
    hasRoles: true,
    hasDatabaseAccess: true
  });
  assert.equal(resolution.resolved, "xhigh");
});

test("auto resolves ultra for a large high-risk surface", () => {
  const resolution = resolveEffort("auto", {
    ...minimal,
    sourceFileCount: 1500,
    routeCount: 120,
    hasAuthentication: true,
    hasRoles: true,
    hasDatabaseAccess: true,
    hasFileUpload: true,
    hasServerSideFetch: true,
    hasPaymentIntegration: true,
    externalTargetCount: 2
  });
  assert.equal(resolution.resolved, "ultra");
});

test("reduced capability is explained in the rationale rather than hidden", () => {
  const resolution = resolveEffort("auto", {
    ...minimal,
    runtimeReachable: false,
    testIdentityCount: 0,
    isolatedRuntimeAvailable: false
  });
  const text = resolution.rationale.join(" ");
  assert.match(text, /No local runtime was reachable/);
  assert.match(text, /two test identities/);
  assert.match(text, /Isolated runtime checks are unavailable/);
  assert.ok(!/error|missing docker/i.test(text), "capability gaps are described calmly");
});
