import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import {
  blocksCloudSync,
  canonicalize,
  compareVersions,
  describeDecision,
  evaluateUpdate,
  findRevocation,
  generateSigningKeyPair,
  signManifest,
  verifyArtifact,
  verifyManifest,
  versionInRange
} from "../dist/index.js";

const keys = generateSigningKeyPair();
const KEY_ID = "release-2026-08";
const TRUSTED = { [KEY_ID]: keys.publicKeyPem };
const ARTIFACT_BODY = Buffer.from("pretend-tarball-bytes");

function manifest(overrides = {}) {
  return {
    schemaVersion: 1,
    releaseVersion: "0.2.0",
    channel: "stable",
    publishedAt: new Date().toISOString(),
    revokedVersions: [],
    artifacts: [
      {
        os: "darwin",
        arch: "arm64",
        url: "https://releases.example.test/myrqen-0.2.0-darwin-arm64.tgz",
        sha256: crypto.createHash("sha256").update(ARTIFACT_BODY).digest("hex"),
        size: ARTIFACT_BODY.byteLength
      }
    ],
    keyId: KEY_ID,
    ...overrides
  };
}

test("canonical serialization is stable regardless of key order", () => {
  assert.equal(canonicalize({ b: 1, a: [3, { d: 4, c: 5 }] }), canonicalize({ a: [3, { c: 5, d: 4 }], b: 1 }));
});

test("a valid signed manifest verifies", () => {
  const signed = signManifest(manifest(), keys.privateKeyPem);
  const result = verifyManifest(signed, { trustedKeys: TRUSTED });
  assert.equal(result.valid, true);
  assert.equal(result.manifest.releaseVersion, "0.2.0");
});

test("a modified payload fails signature verification", () => {
  const signed = signManifest(manifest(), keys.privateKeyPem);
  const tampered = JSON.parse(Buffer.from(signed.payload, "base64").toString("utf8"));
  tampered.artifacts[0].url = "https://evil.test/payload.tgz";
  const forged = { ...signed, payload: Buffer.from(JSON.stringify(tampered)).toString("base64") };
  assert.equal(verifyManifest(forged, { trustedKeys: TRUSTED }).reason, "bad_signature");
});

test("a manifest signed by the wrong key is refused", () => {
  const other = generateSigningKeyPair();
  const signed = signManifest(manifest(), other.privateKeyPem);
  assert.equal(verifyManifest(signed, { trustedKeys: TRUSTED }).reason, "bad_signature");
});

test("an unknown key id is refused before any parsing", () => {
  const signed = signManifest(manifest({ keyId: "attacker-key" }), keys.privateKeyPem);
  assert.equal(verifyManifest(signed, { trustedKeys: TRUSTED }).reason, "unknown_key");
});

test("a manifest whose schema is invalid is refused even with a good signature", () => {
  const signed = signManifest(manifest({ extraField: "arbitrary" }), keys.privateKeyPem);
  assert.equal(verifyManifest(signed, { trustedKeys: TRUSTED }).reason, "schema_invalid");
});

test("stale and future-dated manifests are refused", () => {
  const stale = signManifest(manifest({ publishedAt: "2020-01-01T00:00:00.000Z" }), keys.privateKeyPem);
  assert.equal(verifyManifest(stale, { trustedKeys: TRUSTED }).reason, "stale_manifest");

  const future = signManifest(
    manifest({ publishedAt: new Date(Date.now() + 60 * 60 * 1000).toISOString() }),
    keys.privateKeyPem
  );
  assert.equal(verifyManifest(future, { trustedKeys: TRUSTED }).reason, "future_manifest");
});

test("artifact digest and size are both enforced", () => {
  const entry = manifest().artifacts[0];
  assert.equal(verifyArtifact(ARTIFACT_BODY, entry).ok, true);
  assert.equal(verifyArtifact(Buffer.concat([ARTIFACT_BODY, Buffer.from("x")]), entry).ok, false);
  const wrongDigest = { ...entry, sha256: "0".repeat(64) };
  assert.match(verifyArtifact(ARTIFACT_BODY, wrongDigest).reason, /digest/);
});

test("version comparison and range matching", () => {
  assert.ok(compareVersions("0.2.0", "0.1.9") > 0);
  assert.ok(compareVersions("1.0.0-beta.1", "1.0.0") < 0);
  assert.equal(compareVersions("0.2.0", "0.2.0"), 0);
  assert.equal(versionInRange("0.1.5", "<=0.1.6"), true);
  assert.equal(versionInRange("0.1.7", "<=0.1.6"), false);
  assert.equal(versionInRange("0.1.4", "0.1.3 - 0.1.5"), true);
  assert.equal(versionInRange("0.1.3", "0.1.3"), true);
});

test("a revoked current version blocks sync and names the reason", () => {
  const signed = manifest({ revokedVersions: [{ range: "<=0.1.9", reasonCode: "credential_logging_defect" }] });
  const decision = evaluateUpdate({ manifest: signed, currentVersion: "0.1.5", os: "darwin", arch: "arm64" });
  assert.equal(decision.action, "blocked_revoked");
  assert.equal(decision.reasonCode, "credential_logging_defect");
  assert.equal(blocksCloudSync(decision), true);
  const copy = describeDecision(decision, "myrqen");
  assert.match(copy, /withdrawn/);
  assert.match(copy, /Local reports still open/);
});

test("a version below the minimum blocks sync but not local use", () => {
  const decision = evaluateUpdate({
    manifest: manifest({ minimumClientVersion: "0.2.0" }),
    currentVersion: "0.1.0",
    os: "darwin",
    arch: "arm64"
  });
  assert.equal(decision.action, "blocked_below_minimum");
  assert.equal(blocksCloudSync(decision), true);
});

test("a downgrade offer is refused", () => {
  const decision = evaluateUpdate({
    manifest: manifest({ releaseVersion: "0.1.0" }),
    currentVersion: "0.2.0",
    os: "darwin",
    arch: "arm64"
  });
  assert.equal(decision.action, "refused_downgrade");
  assert.equal(blocksCloudSync(decision), false);
});

test("a pin holds a version but never overrides a revocation", () => {
  const pinned = evaluateUpdate({
    manifest: manifest(),
    currentVersion: "0.1.0",
    pinnedVersion: "0.1.0",
    os: "darwin",
    arch: "arm64"
  });
  assert.equal(pinned.action, "pinned");

  const revoked = evaluateUpdate({
    manifest: manifest({ revokedVersions: [{ range: "0.1.0", reasonCode: "unsafe" }] }),
    currentVersion: "0.1.0",
    pinnedVersion: "0.1.0",
    os: "darwin",
    arch: "arm64"
  });
  assert.equal(revoked.action, "blocked_revoked");
});

test("a missing artifact for this platform is reported, not guessed", () => {
  const decision = evaluateUpdate({ manifest: manifest(), currentVersion: "0.1.0", os: "windows", arch: "x64" });
  assert.equal(decision.action, "no_artifact");
});

test("a manifest for another channel is ignored", () => {
  const decision = evaluateUpdate({
    manifest: manifest({ channel: "canary" }),
    currentVersion: "0.1.0",
    os: "darwin",
    arch: "arm64"
  });
  assert.equal(decision.action, "channel_mismatch");
});

test("revocation lookup returns the matching range", () => {
  const found = findRevocation("0.1.4", [{ range: "0.1.3 - 0.1.5", reasonCode: "x" }]);
  assert.equal(found.reasonCode, "x");
  assert.equal(findRevocation("0.2.0", [{ range: "0.1.3 - 0.1.5", reasonCode: "x" }]), null);
});
