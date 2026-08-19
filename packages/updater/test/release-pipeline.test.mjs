/** The signing script and the client verifier must agree end to end. */
import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { evaluateUpdate, verifyArtifact, verifyManifest } from "../dist/index.js";

const run = promisify(execFile);
const ROOT = path.resolve(import.meta.dirname, "..", "..", "..");

test("a manifest signed by the release script verifies with the pinned public key", async () => {
  const workspace = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-release-"));
  const keyId = "release-pipeline-test";

  await run(process.execPath, [path.join(ROOT, "scripts", "generate-release-key.mjs"), keyId], { cwd: workspace });
  const publicKeyPem = await fs.readFile(path.join(workspace, `${keyId}.public.pem`), "utf8");

  const artifactPath = path.join(workspace, "myrqen-darwin-arm64.tgz");
  const artifactBody = crypto.randomBytes(2048);
  await fs.writeFile(artifactPath, artifactBody);

  const manifestPath = path.join(workspace, "manifest.signed.json");
  await run(
    process.execPath,
    [
      path.join(ROOT, "scripts", "sign-release.mjs"),
      "--version",
      "0.3.0",
      "--artifact",
      `darwin:arm64:${artifactPath}`,
      "--minimum",
      "0.2.0",
      "--revoke",
      "<=0.1.9=credential_logging_defect",
      "--out",
      manifestPath
    ],
    {
      cwd: workspace,
      env: {
        ...process.env,
        MYRQEN_RELEASE_PRIVATE_KEY_FILE: path.join(workspace, `${keyId}.private.pem`),
        MYRQEN_RELEASE_KEY_ID: keyId
      }
    }
  );

  const signed = JSON.parse(await fs.readFile(manifestPath, "utf8"));
  const verification = verifyManifest(signed, { trustedKeys: { [keyId]: publicKeyPem } });
  assert.equal(verification.valid, true, JSON.stringify(verification));
  assert.equal(verification.manifest.releaseVersion, "0.3.0");
  assert.equal(verification.manifest.minimumClientVersion, "0.2.0");

  const artifact = verification.manifest.artifacts[0];
  assert.equal(verifyArtifact(artifactBody, artifact).ok, true);
  assert.equal(verifyArtifact(Buffer.concat([artifactBody, Buffer.from("x")]), artifact).ok, false);

  const current = evaluateUpdate({
    manifest: verification.manifest,
    currentVersion: "0.2.0",
    os: "darwin",
    arch: "arm64"
  });
  assert.equal(current.action, "update_available");

  const revoked = evaluateUpdate({
    manifest: verification.manifest,
    currentVersion: "0.1.5",
    os: "darwin",
    arch: "arm64"
  });
  assert.equal(revoked.action, "blocked_revoked");
  assert.equal(revoked.reasonCode, "credential_logging_defect");

  const otherKey = verifyManifest(signed, { trustedKeys: { "some-other-key": publicKeyPem } });
  assert.equal(otherKey.valid, false);
  assert.equal(otherKey.reason, "unknown_key");
});
