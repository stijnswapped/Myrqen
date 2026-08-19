/**
 * Project discovery must be fast, honest, and impossible to stall. An
 * unresponsive isolated runtime is a common local state and must never block a
 * scan.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

const ROOT = path.resolve(import.meta.dirname, "..", "..", "..");
const { discoverProject, findRepoRoot } = await import(
  path.join(ROOT, "apps", "cli", "dist-tsc", "discovery", "project.js")
);

const FIXTURE = path.join(ROOT, "fixtures", "vuln-shop");

test("the vulnerable fixture is mapped accurately", async () => {
  const discovered = await discoverProject(FIXTURE);

  assert.equal(discovered.name, "myrqen-fixture-vuln-shop");
  assert.ok(discovered.stack.languages.includes("JavaScript"));
  assert.ok(discovered.signals.routeCount > 0, "routes are counted");
  assert.equal(discovered.signals.hasAuthentication, true);
  assert.equal(discovered.signals.hasServerSideFetch, true);
  assert.equal(discovered.signals.hasFileUpload, true);
  assert.ok(discovered.localTargets.some((target) => target.includes("4010")));
});

test("external origins referenced by the project are candidates, never authorized", async () => {
  const discovered = await discoverProject(FIXTURE);
  assert.ok(
    discovered.externalCandidates.some((origin) => origin.includes("payments.example.test")),
    `expected the configured payments origin, got ${discovered.externalCandidates.join(", ")}`
  );
  // Loopback never appears as an external candidate.
  assert.ok(!discovered.externalCandidates.some((origin) => origin.includes("127.0.0.1")));
});

test("secret values are collected from real env files and not from the example", async () => {
  const discovered = await discoverProject(FIXTURE);
  assert.ok(
    discovered.knownSecretValues.includes("mqcanary-9f4b2d61c05a7e38b6d3f7a1e29c7b50"),
    "the canary is available to the redaction matcher"
  );
});

test("instruction-like passages in project content are recorded as untrusted", async () => {
  const discovered = await discoverProject(FIXTURE);
  assert.ok(discovered.injectionObservations.length > 0);
  assert.ok(discovered.injectionObservations.every((observation) => observation.excerpt.length <= 160));
});

test("an unresponsive isolated runtime never stalls discovery", async () => {
  const shim = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-docker-shim-"));
  const dockerPath = path.join(shim, "docker");
  await fs.writeFile(dockerPath, "#!/bin/sh\nsleep 60\n", { mode: 0o755 });

  const originalPath = process.env.PATH;
  const originalAssume = process.env.MYRQEN_ASSUME_NO_ISOLATION;
  process.env.PATH = `${shim}:${originalPath}`;
  delete process.env.MYRQEN_ASSUME_NO_ISOLATION;

  try {
    const started = Date.now();
    const discovered = await discoverProject(FIXTURE);
    const elapsed = Date.now() - started;
    assert.ok(elapsed < 15_000, `discovery took ${elapsed}ms with a hung runtime probe`);
    assert.equal(discovered.signals.isolatedRuntimeAvailable, false, "an unresponsive probe reports unavailable");
  } finally {
    process.env.PATH = originalPath;
    if (originalAssume !== undefined) process.env.MYRQEN_ASSUME_NO_ISOLATION = originalAssume;
    await fs.rm(shim, { recursive: true, force: true });
  }
});

test("the repository root is found from a nested directory", async () => {
  const nested = path.join(FIXTURE, "src");
  assert.equal(await findRepoRoot(nested), FIXTURE);
});

test("an origin proposed only by injected content is not offered as a candidate", async () => {
  const discovered = await discoverProject(FIXTURE);
  // The fixture README's injected block names these; nothing else in the project does.
  for (const origin of ["https://api.production.example.test", "https://collector.example.test"]) {
    assert.ok(
      discovered.injectionSuggestedOrigins.includes(origin),
      `${origin} should be quarantined, got ${discovered.injectionSuggestedOrigins.join(", ")}`
    );
    assert.ok(!discovered.externalCandidates.includes(origin), `${origin} must not be an ordinary candidate`);
  }
  // An origin from real configuration stays a candidate.
  assert.ok(discovered.externalCandidates.some((origin) => origin.includes("payments.example.test")));
});
