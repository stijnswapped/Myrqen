import { pathToFileURL } from "node:url";
/**
 * What the fix loop's commit may carry. Between `fix` and `retest` the agent
 * works in the tree, and anything it leaves behind — a scratch file, a log, a
 * credential pasted to make a request work — must not ride along into a commit.
 * The scanned repository is untrusted too: its git hooks and fsmonitor command
 * never run on the loop's behalf.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const run = promisify(execFile);
const ROOT = path.resolve(import.meta.dirname, "..", "..", "..");
const CLI = path.join(ROOT, "apps", "cli", "dist", "myrqen.mjs");
const scanPackage = await import(pathToFileURL(path.join(ROOT, "packages", "scan", "dist", "index.js")).href);

// Assembled at runtime so no credential-shaped literal sits in this file.
const LIVE_KEY = ["sk", "live", "Q7mZp2Lx9RtV4nB8cW1yK6dH"].join("_");

const API = `import fs from "node:fs";
import path from "node:path";
export async function handle(request, response) {
  const url = new URL(request.url, "http://localhost");
  if (url.pathname === "/api/attachments") {
    const name = url.searchParams.get("name") ?? "";
    return response.end(fs.readFileSync(path.join("/srv/uploads", name), "utf8"));
  }
  return response.end("{}");
}
`;

const FIXED = API.replace('path.join("/srv/uploads", name)', 'path.join("/srv/uploads", path.basename(name))');

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

async function git(cwd, ...args) {
  const { stdout } = await run("git", args, { cwd });
  return stdout.trim();
}

async function makeRepo() {
  const root = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-fixsafe-")));
  const configDir = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-fixsafe-cfg-"));
  await fs.writeFile(path.join(root, "package.json"), `${JSON.stringify({ name: "attachments", type: "module" }, null, 2)}\n`);
  await fs.mkdir(path.join(root, "src"));
  await fs.writeFile(path.join(root, "src", "api.js"), API);
  await git(root, "init", "--quiet", "--initial-branch=main");
  await git(root, "config", "user.email", "dev@example.test");
  await git(root, "config", "user.name", "Dev");
  await git(root, "config", "commit.gpgsign", "false");
  await git(root, "add", "--all");
  await git(root, "commit", "--quiet", "-m", "initial");

  const cli = async (args) => {
    try {
      const { stdout } = await run(process.execPath, [CLI, "--json", ...args], { cwd: root, env: env(configDir), maxBuffer: 32 * 1024 * 1024 });
      return { code: 0, body: JSON.parse(stdout), raw: stdout };
    } catch (error) {
      return { code: error.code, body: error.stdout ? JSON.parse(error.stdout) : null, raw: error.stdout ?? "", stderr: error.stderr };
    }
  };
  const start = await cli(["auto", "--sync", "no"]);
  assert.equal(start.code, 0, JSON.stringify(start));
  const directory = path.join(root, ".myrqen", "sessions");
  const [id] = await fs.readdir(directory);
  const state = JSON.parse(await fs.readFile(path.join(directory, id, "session.json"), "utf8"));
  const traversal = state.findings.find((finding) => finding.category === "path_traversal");
  assert.ok(traversal, state.findings.map((finding) => finding.category).join(", "));
  return { root, configDir, cli, traversal };
}

async function cleanup(...directories) {
  for (const directory of directories) await fs.rm(directory, { recursive: true, force: true });
}

test("the scanner's credential rule reads plain text: lines and labels, never values", () => {
  const text = [
    `const stripe = "${LIVE_KEY}";`,
    'const greeting = "hello world, nothing to see";',
    "DATABASE_URL=postgres://app:Hx92kLmq0Zp@db.prod.example.com:5432/app",
    "LOCAL_URL=postgres://app:Hx92kLmq0Zp@localhost:5432/app",
    'PASSWORD="changeme"',
    `headers: { Authorization: "Bearer " + "${LIVE_KEY}" }`
  ].join("\n");
  const hits = scanPackage.findCredentialsInText(text);
  assert.deepEqual(
    hits.map((hit) => hit.line),
    [1, 3, 6]
  );
  assert.ok(hits.every((hit) => typeof hit.label === "string" && hit.label.length > 0));
  assert.doesNotMatch(JSON.stringify(hits), /Q7mZp2Lx9RtV4nB8cW1yK6dH|Hx92kLmq0Zp/, "a hit names the line, not the value");
});

test("retest commits only tracked changes, and lists untracked files instead of adding them", async () => {
  const { root, configDir, cli, traversal } = await makeRepo();
  try {
    const started = await cli(["fix", traversal.id]);
    assert.equal(started.code, 0, JSON.stringify(started));

    await fs.writeFile(path.join(root, "src", "api.js"), FIXED);
    // The agent's own regression test, added to the index on purpose: included.
    await fs.mkdir(path.join(root, "test"));
    await fs.writeFile(path.join(root, "test", "api.test.js"), "// basename keeps the upload root\n");
    await git(root, "add", "test/api.test.js");
    // Left behind and never staged: not included.
    await fs.mkdir(path.join(root, "scratch"));
    await fs.writeFile(path.join(root, "scratch", "notes.txt"), "tried a few payloads\n");
    await fs.writeFile(path.join(root, "debug.log"), "GET /api/attachments?name=../../etc/passwd\n");

    const retest = await cli(["retest", traversal.id]);
    assert.equal(retest.body.outcome, "pass", JSON.stringify(retest.body));
    assert.ok(retest.body.committed?.sha, JSON.stringify(retest.body));
    const committed = (await git(root, "show", "--name-only", "--format=", "HEAD")).split("\n").sort();
    assert.deepEqual(committed, ["src/api.js", "test/api.test.js"]);
    assert.deepEqual([...retest.body.untracked].sort(), ["debug.log", "scratch/notes.txt"]);
    const status = await git(root, "status", "--porcelain", "--untracked-files=all");
    assert.match(status, /\?\? debug\.log/);
    assert.match(status, /\?\? scratch\/notes\.txt/);
  } finally {
    await cleanup(root, configDir);
  }
});

test("retest refuses to commit a credential and names where it is without printing it", async () => {
  const { root, configDir, cli, traversal } = await makeRepo();
  try {
    await cli(["fix", traversal.id]);
    const head = await git(root, "rev-parse", "HEAD");
    await fs.writeFile(path.join(root, "src", "api.js"), `${FIXED}export const STRIPE_KEY = "${LIVE_KEY}";\n`);

    const retest = await cli(["retest", traversal.id]);
    assert.equal(retest.body.outcome, "pass", "the finding is still fixed; only the commit is refused");
    assert.equal(retest.body.committed, undefined);
    assert.match(retest.body.commitSkipped, /src\/api\.js:11/);
    assert.match(retest.body.commitSkipped, /Stripe/i);
    assert.doesNotMatch(retest.raw, /Q7mZp2Lx9RtV4nB8cW1yK6dH/, "the value appears nowhere in the output");
    assert.deepEqual(retest.body.credentialsFound, [{ file: "src/api.js", line: 11, label: retest.body.credentialsFound[0].label }]);
    assert.equal(await git(root, "rev-parse", "HEAD"), head, "nothing was committed");
  } finally {
    await cleanup(root, configDir);
  }
});

test("the repository's git hooks and fsmonitor never run for the fix loop", { skip: process.platform === "win32" }, async () => {
  const { root, configDir, cli, traversal } = await makeRepo();
  const outside = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-hooks-"));
  try {
    const marker = path.join(outside, "ran");
    const hooks = path.join(root, ".husky");
    await fs.mkdir(hooks);
    for (const hook of ["pre-commit", "commit-msg", "post-commit", "prepare-commit-msg", "post-checkout"]) {
      await fs.writeFile(path.join(hooks, hook), `#!/bin/sh\necho ${hook} >> "${marker}"\nexit 1\n`, { mode: 0o755 });
    }
    await fs.writeFile(path.join(outside, "fsmonitor.sh"), `#!/bin/sh\necho fsmonitor >> "${marker}"\n`, { mode: 0o755 });
    await git(root, "add", ".husky");
    await git(root, "commit", "--quiet", "--no-verify", "-m", "hooks");
    await git(root, "config", "core.hooksPath", ".husky");
    await git(root, "config", "core.fsmonitor", path.join(outside, "fsmonitor.sh"));

    const started = await cli(["fix", traversal.id]);
    assert.equal(started.code, 0, JSON.stringify(started));
    await fs.writeFile(path.join(root, "src", "api.js"), FIXED);
    const retest = await cli(["retest", traversal.id]);
    assert.ok(retest.body.committed?.sha, JSON.stringify(retest.body));

    let ran = "";
    try {
      ran = await fs.readFile(marker, "utf8");
    } catch {
      ran = "";
    }
    assert.equal(ran, "", `nothing from the repository ran: ${ran}`);
  } finally {
    await cleanup(root, configDir, outside);
  }
});
