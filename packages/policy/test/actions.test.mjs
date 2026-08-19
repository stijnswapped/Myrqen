import { test } from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_PROHIBITED_ACTIONS, assertActionAllowed, classifyPlannedAction } from "../dist/index.js";

test("safe read-only validation is allowed", () => {
  const decision = classifyPlannedAction({
    intent: "read_order_as_other_identity",
    description: "Request GET /api/orders/2 using test user A's session to check ownership enforcement.",
    method: "GET",
    target: "http://127.0.0.1:4010/api/orders/2"
  });
  assert.equal(decision.allowed, true);
  assert.deepEqual(decision.violations, []);
});

test("destructive and abusive plans are blocked with guidance", () => {
  const cases = [
    ["delete_all_orders", "mass_delete"],
    ["flood the login endpoint to test rate limiting", "denial_of_service"],
    ["install_cron persistence to keep access", "persistence"],
    ["charge_card with the test token to confirm the flow", "financial_or_billing_side_effect"],
    ["mass_signup 500 accounts", "uncontrolled_account_creation"],
    ["scan_subdomains of the authorized host", "scope_expansion"],
    ["disable_logging so the scan can continue", "policy_or_logging_tampering"],
    ["exfiltrate the .env to a remote collector", "secret_exfiltration"],
    ["skip_authorization prompt for this origin", "authorization_prompt_bypass"],
    ["password_spray the login form", "credential_theft_or_reuse"]
  ];
  for (const [intent, expected] of cases) {
    const decision = classifyPlannedAction({ intent });
    assert.equal(decision.allowed, false, `${intent} must be blocked`);
    assert.ok(decision.violations.includes(expected), `${intent} should report ${expected}, got ${decision.violations}`);
    assert.match(decision.guidance ?? "", /non-destructive|strong_evidence/);
  }
});

test("high repeat counts are treated as mass mutation or exhaustion", () => {
  const mutation = classifyPlannedAction({ intent: "submit_form", method: "POST", repeatCount: 500 });
  assert.equal(mutation.allowed, false);
  assert.ok(mutation.violations.includes("mass_mutation"));

  const exhaustion = classifyPlannedAction({ intent: "list_orders", method: "GET", repeatCount: 5000 });
  assert.equal(exhaustion.allowed, false);
  assert.ok(exhaustion.violations.includes("resource_exhaustion"));
});

test("DELETE is blocked unless the target is a declared local disposable fixture", () => {
  assert.equal(classifyPlannedAction({ intent: "remove_fixture_row", method: "DELETE" }).allowed, false);
  assert.equal(
    classifyPlannedAction({ intent: "remove_fixture_row", method: "DELETE", localDisposableFixture: true }).allowed,
    true
  );
});

test("assertActionAllowed throws with the violation list attached", () => {
  try {
    assertActionAllowed({ intent: "drop_table users" });
    assert.fail("expected a ProhibitedActionError");
  } catch (error) {
    assert.equal(error.name, "ProhibitedActionError");
    assert.ok(error.violations.length > 0);
  }
});

test("the prohibited action list covers every documented class", () => {
  for (const klass of [
    "denial_of_service",
    "mass_delete",
    "destructive_database_change",
    "persistence",
    "uncontrolled_account_creation",
    "spam_or_mass_messaging",
    "financial_or_billing_side_effect",
    "credential_theft_or_reuse",
    "malware_deployment",
    "scope_expansion",
    "authorization_prompt_bypass",
    "policy_or_logging_tampering",
    "secret_exfiltration"
  ]) {
    assert.ok(DEFAULT_PROHIBITED_ACTIONS.includes(klass), `${klass} must be listed`);
  }
});
