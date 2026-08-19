import { test } from "node:test";
import assert from "node:assert/strict";
import {
  assertNoScopeExpansion,
  buildAuthorizationPrompt,
  classifyRedirect,
  describeScopeRefusal,
  exactOriginAuthorized,
  externalTargetPosture,
  normalizeHttpTarget,
  requiresExternalAuthorization
} from "../dist/index.js";

test("loopback and localhost targets are in scope without an authorization prompt", () => {
  for (const target of [
    "http://localhost:3000",
    "http://127.0.0.1:4010/api",
    "http://app.localhost:8080",
    "https://[::1]:8443",
    "http://host.docker.internal:5000"
  ]) {
    assert.equal(requiresExternalAuthorization(target), false, `${target} should be local`);
  }
});

test("private LAN addresses are not treated as local and still require authorization", () => {
  for (const target of ["http://192.168.1.20:3000", "http://10.0.0.5", "http://172.20.3.4", "http://printer.local"]) {
    assert.equal(requiresExternalAuthorization(target), true, `${target} must require authorization`);
    assert.equal(normalizeHttpTarget(target).privateNetwork, true);
  }
});

test("authorization is exact: approving api.example.com does not approve neighbours", () => {
  const authorized = ["https://api.example.com"];
  assert.equal(exactOriginAuthorized("https://api.example.com/v1/orders", authorized), true);
  for (const sibling of [
    "https://example.com",
    "https://admin.example.com",
    "https://api.example.com.evil.test",
    "http://api.example.com",
    "https://api.example.com:8443",
    "https://staging-api.example.com",
    "https://cdn.example.com"
  ]) {
    assert.equal(exactOriginAuthorized(sibling, authorized), false, `${sibling} must not be authorized`);
    assert.throws(() => assertNoScopeExpansion(sibling, authorized), /requires explicit authorization|not authorized/i);
  }
});

test("credentials embedded in a target URL are stripped from the normalized origin", () => {
  const normalized = normalizeHttpTarget("https://user:secretpassword@api.example.com/x");
  assert.equal(normalized.origin, "https://api.example.com");
  assert.ok(!normalized.origin.includes("secretpassword"));
});

test("malformed stored origins cannot widen scope", () => {
  assert.equal(exactOriginAuthorized("https://api.example.com", ["not a url", ""]), false);
});

test("cross-origin redirects are gated rather than followed", () => {
  const authorized = ["https://api.example.com"];
  assert.deepEqual(classifyRedirect("https://api.example.com/a", "https://api.example.com/b", authorized), {
    decision: "follow",
    reason: "same_origin"
  });
  const blocked = classifyRedirect("https://api.example.com/a", "https://login.example.com/", authorized);
  assert.equal(blocked.decision, "block");
  assert.equal(blocked.origin, "https://login.example.com");
  assert.equal(
    classifyRedirect("http://127.0.0.1:3000/a", "http://localhost:3000/b", []).decision,
    "follow",
    "local-to-local redirects stay in scope"
  );
});

test("external posture stays restrictive after authorization", () => {
  const posture = externalTargetPosture();
  assert.equal(posture.maxConcurrency, 1);
  assert.ok(posture.minDelayMs > 0);
  assert.deepEqual([...posture.allowedMethods], ["GET", "HEAD", "OPTIONS"]);
  assert.equal(posture.followCrossOriginRedirects, false);
  assert.equal(posture.stopOnProductionIndicators, true);
});

test("authorization prompt shows the exact origin and defaults to no", () => {
  const prompt = buildAuthorizationPrompt("https://api.example.com");
  assert.match(prompt, /https:\/\/api\.example\.com/);
  assert.match(prompt, /\[y\/N\]$/);
  assert.match(prompt, /own it or have permission/);
});

test("refusal copy explains exactness without scary infrastructure language", () => {
  const text = describeScopeRefusal("https://admin.example.com", ["https://api.example.com"]);
  assert.match(text, /outside the authorized scope/);
  assert.match(text, /subdomains/);
  assert.ok(!/danger|attack|hack/i.test(text));
});

test("non-http protocols are refused by the policy helper", () => {
  assert.throws(() => normalizeHttpTarget("file:///etc/passwd"), /http\/https/);
  assert.throws(() => normalizeHttpTarget("not-a-url"), /not a valid absolute/);
});
