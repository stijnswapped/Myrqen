#!/usr/bin/env node
/**
 * Produces a signed release manifest for the updater.
 *
 * The private key never lives in the repository. Pass it by path or by
 * environment variable, and keep it outside ordinary CI runners.
 *
 *   node scripts/generate-release-key.mjs                     # once, offline
 *   MYRQEN_RELEASE_PRIVATE_KEY_FILE=key.pem \
 *     node scripts/sign-release.mjs --version 0.2.0 --artifact darwin:arm64:dist/myrqen-darwin-arm64.tgz
 */
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { canonicalize, signManifest } from "../packages/updater/dist/index.js";

const argv = process.argv.slice(2);

function option(name, fallback = null) {
  const index = argv.indexOf(`--${name}`);
  if (index === -1) return fallback;
  const value = argv[index + 1];
  return value && !value.startsWith("--") ? value : true;
}

function options(name) {
  const values = [];
  argv.forEach((token, index) => {
    if (token === `--${name}`) values.push(argv[index + 1]);
  });
  return values.filter(Boolean);
}

const version = option("version");
if (!version) {
  process.stderr.write("--version is required.\n");
  process.exit(1);
}

const keyFile = process.env.MYRQEN_RELEASE_PRIVATE_KEY_FILE ?? option("key");
const inlineKey = process.env.MYRQEN_RELEASE_PRIVATE_KEY;
if (!keyFile && !inlineKey) {
  process.stderr.write("Set MYRQEN_RELEASE_PRIVATE_KEY_FILE or MYRQEN_RELEASE_PRIVATE_KEY.\n");
  process.exit(1);
}
const privateKeyPem = inlineKey ?? (await fs.readFile(keyFile, "utf8"));
const keyId = process.env.MYRQEN_RELEASE_KEY_ID ?? option("key-id", "release-dev");

const artifacts = [];
for (const spec of options("artifact")) {
  const [os, arch, file] = spec.split(":");
  if (!os || !arch || !file) {
    process.stderr.write(`--artifact must look like os:arch:path (got "${spec}")\n`);
    process.exit(1);
  }
  const body = await fs.readFile(file);
  artifacts.push({
    os,
    arch,
    url: `${option("base-url", "https://releases.myrqen.invalid")}/${version}/${path.basename(file)}`,
    sha256: crypto.createHash("sha256").update(body).digest("hex"),
    size: body.byteLength
  });
}

const revoked = options("revoke").map((entry) => {
  // Ranges contain "=" (for example "<=0.1.9"), so split on the last separator.
  const separator = entry.lastIndexOf("=");
  if (separator <= 0) return { range: entry, reasonCode: "unspecified" };
  return { range: entry.slice(0, separator), reasonCode: entry.slice(separator + 1) || "unspecified" };
});

const manifest = {
  schemaVersion: 1,
  releaseVersion: version,
  channel: option("channel", "stable"),
  publishedAt: new Date().toISOString(),
  ...(option("minimum") ? { minimumClientVersion: option("minimum") } : {}),
  revokedVersions: revoked,
  artifacts,
  keyId
};

const signed = signManifest(manifest, privateKeyPem);
const outputPath = option("out", path.join("release", "manifest.signed.json"));
await fs.mkdir(path.dirname(outputPath), { recursive: true });
await fs.writeFile(outputPath, `${JSON.stringify(signed, null, 2)}\n`, "utf8");

process.stdout.write(`signed ${version} (${artifacts.length} artifact(s)) with key ${keyId}\n`);
process.stdout.write(`canonical bytes: ${canonicalize(manifest).length}\n`);
process.stdout.write(`wrote ${outputPath}\n`);
