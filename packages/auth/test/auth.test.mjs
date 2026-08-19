import { test } from "node:test";
import assert from "node:assert/strict";
import {
  assertPasswordAcceptable,
  createDeviceCredential,
  createLinkRequestIdentifiers,
  createSessionToken,
  generateRecoveryCodes,
  hashPassword,
  hashRecoveryCode,
  hashToken,
  isPlausibleEmail,
  normalizeEmail,
  parseDeviceToken,
  recoveryCodeMatches,
  sessionCookieOptions,
  verifyPassword
} from "../dist/index.js";

test("password hashing is salted, versioned, and verifiable", async () => {
  const hash = await hashPassword("correct horse battery staple");
  assert.match(hash, /^scrypt\$1\$/);
  assert.equal(await verifyPassword("correct horse battery staple", hash), true);
  assert.equal(await verifyPassword("wrong password entirely", hash), false);

  const second = await hashPassword("correct horse battery staple");
  assert.notEqual(hash, second, "each hash uses a fresh salt");
});

test("a malformed stored hash never authenticates", async () => {
  for (const stored of ["", "plaintext", "scrypt$9$1$1$1$aa$bb", "scrypt$1$x$y$z$aa$bb"]) {
    assert.equal(await verifyPassword("anything", stored), false);
  }
});

test("weak passwords are refused with an explicit error", () => {
  assert.throws(() => assertPasswordAcceptable("short"), /at least 12 characters/);
  assert.throws(() => assertPasswordAcceptable("x".repeat(300)), /at most 200 characters/);
  assert.doesNotThrow(() => assertPasswordAcceptable("a reasonable passphrase"));
});

test("device tokens carry a key id and a secret that is stored only as a hash", () => {
  const credential = createDeviceCredential();
  assert.match(credential.token, /^myrq_dev_/);
  const parsed = parseDeviceToken(credential.token);
  assert.equal(parsed.keyId, credential.keyId);
  assert.equal(parsed.secret, credential.secret);
  assert.notEqual(hashToken(credential.secret), credential.secret);
  assert.equal(parseDeviceToken("bearer abc"), null);
  assert.equal(parseDeviceToken("myrq_dev_nodot"), null);
});

test("link request identifiers keep the verifier off the approval URL", () => {
  const identifiers = createLinkRequestIdentifiers();
  assert.match(identifiers.publicRequestId, /^req_[A-Za-z0-9_-]{20,}$/);
  assert.ok(!identifiers.publicRequestId.includes(identifiers.verifier));
  assert.equal(identifiers.verifierHash, hashToken(identifiers.verifier));
});

test("recovery codes are human-transcribable and matched by hash", () => {
  const codes = generateRecoveryCodes();
  assert.equal(codes.length, 10);
  for (const code of codes) assert.match(code, /^[A-Z2-9]{5}-[A-Z2-9]{5}-[A-Z2-9]{5}$/);
  assert.equal(new Set(codes).size, 10);

  const stored = hashRecoveryCode(codes[0]);
  assert.equal(recoveryCodeMatches(codes[0].toLowerCase(), stored), true);
  assert.equal(recoveryCodeMatches(codes[0].replaceAll("-", " "), stored), true);
  assert.equal(recoveryCodeMatches(codes[1], stored), false);
});

test("session cookies are httpOnly, lax, and scoped to the site root", () => {
  const options = sessionCookieOptions(true);
  assert.equal(options.httpOnly, true);
  assert.equal(options.sameSite, "lax");
  assert.equal(options.secure, true);
  assert.equal(options.path, "/");
});

test("session tokens are opaque and expire", () => {
  const now = new Date("2026-08-18T00:00:00Z");
  const session = createSessionToken(now);
  assert.ok(session.token.length >= 40);
  assert.equal(session.tokenHash, hashToken(session.token));
  assert.ok(session.expiresAt.getTime() > now.getTime());
});

test("email normalization and plausibility checks", () => {
  assert.equal(normalizeEmail("  Dev@Example.COM "), "dev@example.com");
  assert.equal(isPlausibleEmail("dev@example.com"), true);
  assert.equal(isPlausibleEmail("dev@localhost"), false);
  assert.equal(isPlausibleEmail("no-at-sign"), false);
});
