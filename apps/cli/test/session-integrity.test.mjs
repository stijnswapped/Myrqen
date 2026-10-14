/**
 * Session state under `.myrqen/` lives inside the repository being scanned, so a
 * repository can ship its own. Nothing read from it is trusted: the repository
 * root must be this one, ids must have the shape the CLI gives them, and every
 * path built from them must stay inside `<repoRoot>/.myrqen`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { pathToFileURL } from "node:url";

const run = promisify(execFile);
const ROOT = path.resolve(import.meta.dirname, "..", "..", "..");
const CLI = path.join(ROOT, "apps", "cli", "dist", "myrqen.mjs");
const DIST = path.join(ROOT, "apps", "cli", "dist-tsc");
const paths = await import(pathToFileURL(path.join(DIST, "config", "paths.js")).href);
const record = await import(pathToFileURL(path.join(DIST, "fix", "record.js")).href);
const stateModule = await import(pathToFileURL(path.join(DIST, "session", "state.js")).href);

const VALID_ID = "rpt_6d7b9706-ca9c-4676-895d-ec400079c71c";

function env(configDir) {
  const value = {
    ...process.env,
    MYRQEN_TELEMETRY: "off",
    MYRQEN_ASSUME_NO_ISOLATION: "1",
    MYRQEN_AGENT_NAME: "test-harness",
    MYRQEN_CONFIG_DIR: configDir
  };
  delete value.CLAUDECODE;
  delete value.AI_AGENT;
  return value;
}

async function cli(cwd, configDir, args) {
  try {
    const { stdout, stderr } = await run(process.execPath, [CLI, "--json", ...args], { cwd, env: env(configDir), maxBuffer: 32 * 1024 * 1024 });
    return { code: 0, body: JSON.parse(stdout), stderr };
  } catch (error) {
    return { code: error.code, body: error.stdout ? JSON.parse(error.stdout) : null, stderr: error.stderr };
  }
}

async function makeSessionProject() {
  const root = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-integrity-")));
  const configDir = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-integrity-cfg-"));
  await fs.writeFile(path.join(root, "package.json"), JSON.stringify({ name: "x", type: "module", dependencies: { lodash: "4.17.11" } }));
  const started = await cli(root, configDir, ["auto", "--sync", "no"]);
  assert.equal(started.code, 0, JSON.stringify(started));
  const id = started.body.localReportId;
  const file = path.join(root, ".myrqen", "sessions", id, "session.json");
  return { root, configDir, id, file };
}

async function cleanup(...directories) {
  for (const directory of directories) await fs.rm(directory, { recursive: true, force: true });
}

async function edit(file, change) {
  const state = JSON.parse(await fs.readFile(file, "utf8"));
  change(state);
  await fs.writeFile(file, JSON.stringify(state, null, 2));
}

test("path builders refuse ids that would leave .myrqen", () => {
  const root = path.resolve(os.tmpdir(), "repo");
  for (const bad of ["../../etc", "..", "rpt_../../x", "/etc/passwd", "a/../../b", ""]) {
    assert.throws(() => paths.sessionDirectory(root, bad), /local report id/, bad);
    assert.throws(() => paths.reportDirectory(root, bad), /local report id/, bad);
  }
  assert.equal(paths.sessionDirectory(root, VALID_ID), path.join(root, ".myrqen", "sessions", VALID_ID));
  for (const bad of ["../x", "..", "a/b", "x".repeat(33), "MYR-001\n", ""]) {
    assert.throws(() => record.fixDirectory(root, VALID_ID, bad), /finding id/, JSON.stringify(bad));
  }
  assert.equal(record.fixDirectory(root, VALID_ID, "MYR-001"), path.join(root, ".myrqen", "fixes", VALID_ID, "MYR-001"));
  assert.throws(() => paths.assertInsideStateDirectory(root, path.join(root, ".myrqen-evil", "x")), /outside/);
  assert.throws(() => paths.assertInsideStateDirectory(root, path.join(root, ".myrqen", "..", "x")), /outside/);
});

test("a session whose repository root is not this repository is refused", async () => {
  const { root, configDir, file } = await makeSessionProject();
  try {
    await edit(file, (state) => {
      state.repoRoot = "/tmp/somewhere-else";
    });
    const result = await cli(root, configDir, ["finding", "list"]);
    assert.equal(result.code, 1);
    assert.match(result.body.error.message, /belongs to .*somewhere-else|repository root/i);
    assert.match(result.body.error.message, /session\.json/);
  } finally {
    await cleanup(root, configDir);
  }
});

test("a session whose id does not match its directory, or has a hostile finding id, is refused", async () => {
  const { root, configDir, file } = await makeSessionProject();
  try {
    const original = await fs.readFile(file, "utf8");
    await edit(file, (state) => {
      state.localReportId = VALID_ID;
    });
    let result = await cli(root, configDir, ["finding", "list"]);
    assert.equal(result.code, 1);
    assert.match(result.body.error.message, /does not match its directory|local report id/i);

    await fs.writeFile(file, original);
    await edit(file, (state) => {
      state.findings[0].id = "../../../../tmp/owned";
    });
    result = await cli(root, configDir, ["finding", "list"]);
    assert.equal(result.code, 1);
    assert.match(result.body.error.message, /finding id/i);

    await fs.writeFile(file, original);
    await edit(file, (state) => {
      state.secretSources = ["../../../../etc/hosts"];
    });
    result = await cli(root, configDir, ["finding", "list"]);
    assert.equal(result.code, 1);
    assert.match(result.body.error.message, /secret source/i);

    await fs.writeFile(file, "{ not json");
    result = await cli(root, configDir, ["finding", "list"]);
    assert.equal(result.code, 1);
    assert.match(result.body.error.message, /not valid JSON|corrupt/i);
  } finally {
    await cleanup(root, configDir);
  }
});

test("a hostile --session value or current-session pointer never becomes a path", async () => {
  const { root, configDir } = await makeSessionProject();
  try {
    let result = await cli(root, configDir, ["--session", "../../../../etc", "finding", "list"]);
    assert.equal(result.code, 1);
    assert.match(result.body.error.message, /not a valid local report id/);

    await fs.writeFile(path.join(root, ".myrqen", "current-session"), "../../../../tmp/evil\n");
    result = await cli(root, configDir, ["finding", "list"]);
    assert.equal(result.code, 1);
    assert.match(result.body.error.message, /not a valid local report id/);
  } finally {
    await cleanup(root, configDir);
  }
});

test("listing runs skips a corrupted session with a warning instead of trusting it", async () => {
  const { root, configDir, id } = await makeSessionProject();
  try {
    const forged = path.join(root, ".myrqen", "sessions", VALID_ID);
    await fs.mkdir(forged, { recursive: true });
    const original = JSON.parse(await fs.readFile(path.join(root, ".myrqen", "sessions", id, "session.json"), "utf8"));
    await fs.writeFile(path.join(forged, "session.json"), JSON.stringify({ ...original, localReportId: VALID_ID, repoRoot: "/elsewhere" }));
    await fs.mkdir(path.join(root, ".myrqen", "sessions", "not-a-session"), { recursive: true });

    const result = await cli(root, configDir, ["reports"]);
    assert.equal(result.code, 0, JSON.stringify(result));
    assert.deepEqual(result.body.reports.map((report) => report.localReportId), [id]);
    assert.match(result.stderr, new RegExp(VALID_ID));

    const listed = await stateModule.listSessions(root, { warnings: [] });
    assert.deepEqual(listed.map((state) => state.localReportId), [id]);
  } finally {
    await cleanup(root, configDir);
  }
});

test("a fix record that does not match its finding is refused", async () => {
  const root = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-fixrec-")));
  try {
    const directory = record.fixDirectory(root, VALID_ID, "MYR-001");
    await fs.mkdir(directory, { recursive: true });
    const good = {
      version: 1,
      findingId: "MYR-001",
      localReportId: VALID_ID,
      branch: "myrqen/fix-MYR-001",
      baseBranch: "main",
      baseCommit: "a".repeat(40),
      mode: "deterministic",
      createdAt: new Date().toISOString(),
      deterministic: { files: ["package.json"], summary: ["x"] },
      retests: []
    };
    await fs.writeFile(path.join(directory, "fix.json"), JSON.stringify(good));
    assert.equal((await record.readFixRecord(root, VALID_ID, "MYR-001")).branch, "myrqen/fix-MYR-001");

    for (const tamper of [
      { findingId: "MYR-002" },
      { localReportId: "rpt_00000000-0000-0000-0000-000000000000" },
      { branch: "main" },
      { deterministic: { files: ["../../outside.txt"], summary: [] } },
      { deterministic: { files: ["/etc/passwd"], summary: [] } },
      { deterministic: { files: [".myrqen/sessions/x"], summary: [] } }
    ]) {
      await fs.writeFile(path.join(directory, "fix.json"), JSON.stringify({ ...good, ...tamper }));
      await assert.rejects(record.readFixRecord(root, VALID_ID, "MYR-001"), /fix record/i, JSON.stringify(tamper));
    }
  } finally {
    await cleanup(root);
  }
});
