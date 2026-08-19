import { test } from "node:test";
import assert from "node:assert/strict";
import {
  assertSafeProgressMessage,
  containsSecretLikeMaterial,
  extractEnvSecretValues,
  fingerprintSecret,
  looksHighEntropySecret,
  redactDeep,
  redactText
} from "../dist/index.js";
import { SHAPES } from "./shapes.mjs";

const CANARY = "myrqen-canary-2f8c1a94d7be4c5f9a13";
const VERTICAL_TAB = String.fromCharCode(11);

test("a known local secret value is replaced everywhere it appears", () => {
  const text = `Authorization header used ${CANARY} and the body repeated ${CANARY}.`;
  const result = redactText(text, [CANARY]);
  assert.ok(!result.value.includes(CANARY));
  assert.equal(result.replacements, 2);
  assert.ok(result.labels.includes("known_local_secret"));
});

test("common credential shapes are detected without a known-secret list", () => {
  const samples = [
    SHAPES.stripeLive,
    SHAPES.bearer,
    SHAPES.jwt,
    SHAPES.awsAccessKey,
    SHAPES.githubToken,
    SHAPES.googleApiKey,
    SHAPES.connectionString,
    SHAPES.envAssignment
  ];
  for (const sample of samples) {
    assert.equal(containsSecretLikeMaterial(sample), true, `${sample} should be detected`);
  }
});

test("connection string redaction keeps the useful prefix and drops the password", () => {
  const result = redactText("postgres://app:supersecretvalue@db.internal:5432/app");
  assert.ok(!result.value.includes("supersecretvalue"));
  assert.match(result.value, /postgres:\/\/app:\[REDACTED_SECRET\]@/);
});

test("deep redaction walks nested finding structures", () => {
  const finding = {
    title: "Secret in config",
    evidence: [{ kind: "source", description: `value is ${CANARY}`, snippet: `const key = "${CANARY}";` }],
    nested: { list: [{ note: CANARY }] }
  };
  const { value, replacements } = redactDeep(finding, [CANARY]);
  const serialized = JSON.stringify(value);
  assert.ok(!serialized.includes(CANARY));
  assert.ok(replacements >= 3);
});

test("progress messages containing secret-like material are rejected, not rewritten", () => {
  assert.doesNotThrow(() => assertSafeProgressMessage("Validating candidate findings"));
  assert.throws(() => assertSafeProgressMessage(`token ${CANARY}`, [CANARY]), /secret-like/);
  assert.throws(() => assertSafeProgressMessage("Bearer abcdefghijklmnopqrstuvwx"), /secret-like/);
  assert.throws(() => assertSafeProgressMessage("x".repeat(301)), /safe length/);
  assert.throws(() => assertSafeProgressMessage(`line${VERTICAL_TAB}break`), /control characters/);
});

test("secret fingerprints are keyed, stable, and never contain the value", () => {
  const a = fingerprintSecret(CANARY, "device-local-key", { label: "STRIPE_SECRET_KEY", kind: "api_key" });
  const b = fingerprintSecret(CANARY, "device-local-key", { label: "STRIPE_SECRET_KEY", kind: "api_key" });
  const other = fingerprintSecret(CANARY, "different-device-key", { label: "STRIPE_SECRET_KEY", kind: "api_key" });
  assert.equal(a.fingerprint, b.fingerprint);
  assert.notEqual(a.fingerprint, other.fingerprint, "a different local key yields a different fingerprint");
  assert.ok(!a.fingerprint.includes(CANARY));
  assert.match(a.fingerprint, /^fp_[A-Za-z0-9_-]{10,}$/);
});

test("dotenv parsing collects candidate secret values and skips comments and trivia", () => {
  const values = extractEnvSecretValues(
    [
      "# comment",
      "DEBUG=true",
      "PORT=4010",
      `STRIPE_SECRET_KEY=${SHAPES.stripeLive}`,
      "export SESSION_SECRET='another-long-secret-value'",
      "EMPTY="
    ].join("\n")
  );
  assert.ok(values.includes(SHAPES.stripeLive));
  assert.ok(values.includes("another-long-secret-value"));
  assert.ok(!values.includes("true"));
  assert.ok(!values.includes("4010"));
});

test("entropy heuristic separates random tokens from prose", () => {
  assert.equal(looksHighEntropySecret("aZ8kQ2vTn5Lp9Xr4Wb7Yc1De"), true);
  assert.equal(looksHighEntropySecret("this is just a sentence"), false);
  assert.equal(looksHighEntropySecret("short1"), false);
});
