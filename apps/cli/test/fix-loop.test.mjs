import { pathToFileURL } from "node:url";
/**
 * The fix loop end to end in a real git repository: refuse a dirty tree, branch
 * per finding, apply only mechanical fixes itself, retest just that finding,
 * commit on the fix branch only after a pass, and never touch the user's branch.
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
const { fixedIn } = await import(pathToFileURL(path.join(ROOT, "packages", "scan", "dist", "index.js")).href);
const CLI = path.join(ROOT, "apps", "cli", "dist", "myrqen.mjs");

const API = `import fs from "node:fs";
import path from "node:path";
import { exec } from "node:child_process";
export async function handle(request, response) {
  const url = new URL(request.url, "http://localhost");
  if (url.pathname === "/api/attachments") {
    const name = url.searchParams.get("name") ?? "";
    return response.end(fs.readFileSync(path.join("/srv/uploads", name), "utf8"));
  }
  if (url.pathname === "/api/convert") {
    const file = url.searchParams.get("file");
    exec("convert " + file + " out.png");
    return response.end("queued");
  }
  return response.end("{}");
}
`;

function env() {
  const value = { ...process.env, MYRQEN_TELEMETRY: "off", MYRQEN_ASSUME_NO_ISOLATION: "1", MYRQEN_AGENT_NAME: "test-harness" };
  delete value.CLAUDECODE;
  delete value.AI_AGENT;
  return value;
}

async function cli(cwd, args) {
  try {
    const { stdout } = await run(process.execPath, [CLI, "--json", ...args], { cwd, env: env(), maxBuffer: 32 * 1024 * 1024 });
    return { code: 0, body: JSON.parse(stdout) };
  } catch (error) {
    return { code: error.code, body: error.stdout ? JSON.parse(error.stdout) : null, stderr: error.stderr };
  }
}

async function git(cwd, ...args) {
  const { stdout } = await run("git", args, { cwd });
  return stdout.trim();
}

async function makeRepo() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-fix-"));
  await fs.writeFile(
    path.join(root, "package.json"),
    `${JSON.stringify({ name: "attachments", type: "module", dependencies: { lodash: "=4.17.11", minimist: "1.2.0" } }, null, 2)}\n`
  );
  await fs.mkdir(path.join(root, "src"));
  await fs.writeFile(path.join(root, "src", "api.js"), API);
  await git(root, "init", "--quiet", "--initial-branch=main");
  await git(root, "config", "user.email", "dev@example.test");
  await git(root, "config", "user.name", "Dev");
  await git(root, "config", "commit.gpgsign", "false");
  await git(root, "add", "--all");
  await git(root, "commit", "--quiet", "-m", "initial");
  return root;
}

async function session(root) {
  const directory = path.join(root, ".myrqen", "sessions");
  const [id] = await fs.readdir(directory);
  return JSON.parse(await fs.readFile(path.join(directory, id, "session.json"), "utf8"));
}

test("the fix loop branches, fixes, retests, and commits only on its own branch", async () => {
  const root = await makeRepo();
  try {
    const start = await cli(root, ["auto", "--sync", "no"]);
    assert.equal(start.code, 0);
    const main = await git(root, "rev-parse", "main");
    const findings = (await session(root)).findings;
    const dependency = findings.find((finding) => finding.category === "dependency_with_known_advisory");
    const traversal = findings.find((finding) => finding.category === "path_traversal");
    const injection = findings.find((finding) => finding.category === "command_injection");
    assert.ok(dependency && traversal && injection, findings.map((finding) => finding.category).join(", "));

    // 1. A dirty tree is refused, and the refusal names the file.
    await fs.writeFile(path.join(root, "notes.txt"), "mine\n");
    const dirty = await cli(root, ["fix", dependency.id]);
    assert.equal(dirty.code, 1);
    assert.match(dirty.body.error.message, /uncommitted changes/);
    assert.match(dirty.body.error.message, /notes\.txt/);
    assert.equal(await git(root, "branch", "--show-current"), "main", "no branch was created");
    await fs.rm(path.join(root, "notes.txt"));

    // 2. A mechanical fix: the dependency is bumped inside its major version.
    const fixed = await cli(root, ["fix", dependency.id]);
    assert.equal(fixed.code, 0, JSON.stringify(fixed));
    assert.equal(fixed.body.mode, "deterministic");
    assert.equal(fixed.body.branch, `myrqen/fix-${dependency.id}`);
    assert.equal(fixed.body.baseBranch, "main");
    assert.equal(await git(root, "branch", "--show-current"), `myrqen/fix-${dependency.id}`);
    const manifest = JSON.parse(await fs.readFile(path.join(root, "package.json"), "utf8"));
    // The target release comes from the scanner's advisory snapshot, so it moves when the
    // snapshot is refreshed; the test asks the snapshot rather than hard-coding it.
    const lodashFixed = fixedIn("lodash", "4.17.11");
    assert.match(lodashFixed, /^4\./, "the first fixed lodash release stays on major 4");
    assert.deepEqual(manifest.dependencies, { lodash: `=${lodashFixed}`, minimist: fixedIn("minimist", "1.2.0") }, "range operators are preserved");

    const passed = await cli(root, ["retest", dependency.id]);
    assert.equal(passed.code, 0, JSON.stringify(passed));
    assert.equal(passed.body.outcome, "pass");
    assert.ok(passed.body.committed?.sha, JSON.stringify(passed.body));
    const message = await git(root, "log", "-1", "--format=%B");
    assert.match(message, new RegExp(`^fix\\(security\\): .+ \\(${dependency.id}\\)`));
    assert.match(message, /static: rule dependency-advisory no longer reports this location/);
    assert.equal(await git(root, "rev-parse", "main"), main, "the user's branch is untouched");
    assert.equal(await git(root, "status", "--porcelain"), "", "everything the fix changed was committed");
    let state = await session(root);
    assert.equal(state.findings.find((finding) => finding.id === dependency.id).status, "fixed_verified");

    // 3. An agent fix: a plan and a prompt, then a retest that fails until the code changes.
    await git(root, "switch", "--quiet", "main");
    const planned = await cli(root, ["fix", traversal.id]);
    assert.equal(planned.body.mode, "agent");
    assert.equal(planned.body.needsRuntimeEvidence, false, "a static candidate is closed by its rule");
    assert.match(planned.body.prompt, new RegExp(`myrqen retest ${traversal.id}`));
    assert.doesNotMatch(planned.body.prompt, /fix record .* --report/, "the generic tail is replaced by the loop's");
    await fs.access(planned.body.planFile);

    const failing = await cli(root, ["retest", traversal.id]);
    assert.equal(failing.code, 6);
    assert.equal(failing.body.outcome, "fail");

    const source = await fs.readFile(path.join(root, "src", "api.js"), "utf8");
    await fs.writeFile(
      path.join(root, "src", "api.js"),
      source.replace('path.join("/srv/uploads", name)', 'path.join("/srv/uploads", path.basename(name))')
    );
    const green = await cli(root, ["retest", traversal.id]);
    assert.equal(green.body.outcome, "pass", JSON.stringify(green.body));
    assert.ok(green.body.committed);
    assert.equal(await git(root, "rev-parse", "main"), main);

    // 4. A runtime-verified finding cannot be closed by the static engine alone.
    await git(root, "switch", "--quiet", "main");
    await cli(root, [
      "finding",
      "verify",
      injection.id,
      "--description",
      "GET /api/convert?file=a.png;id ran the injected command in the local fixture."
    ]);
    await cli(root, ["fix", injection.id]);
    const patched = (await fs.readFile(path.join(root, "src", "api.js"), "utf8"))
      .replace('import { exec } from "node:child_process";', 'import { execFile } from "node:child_process";')
      .replace('exec("convert " + file + " out.png");', 'execFile("convert", [file, "out.png"]);');
    await fs.writeFile(path.join(root, "src", "api.js"), patched);
    const waiting = await cli(root, ["retest", injection.id]);
    assert.equal(waiting.code, 5);
    assert.equal(waiting.body.outcome, "needs_runtime_evidence");
    assert.equal(await git(root, "rev-parse", "HEAD"), await git(root, "rev-parse", "main"), "nothing committed without proof");

    const proven = await cli(root, [
      "retest",
      injection.id,
      "--evidence",
      "GET /api/convert?file=a.png;id now returns queued and no extra process runs."
    ]);
    assert.equal(proven.body.outcome, "pass", JSON.stringify(proven.body));
    assert.ok(proven.body.committed);
    assert.match(await git(root, "log", "-1", "--format=%B"), /runtime: no longer reproduces/);

    // 5. Never a commit on the user's branch, even when a retest passes there.
    await git(root, "switch", "--quiet", "main");
    await fs.writeFile(path.join(root, "src", "api.js"), source.replace('path.join("/srv/uploads", name)', 'path.join("/srv/uploads", path.basename(name))'));
    const elsewhere = await cli(root, ["retest", traversal.id]);
    assert.equal(elsewhere.body.outcome, "pass");
    assert.equal(elsewhere.body.committed, undefined);
    assert.match(elsewhere.body.commitSkipped, /only commits on the fix branch/);
    assert.equal(await git(root, "rev-parse", "main"), main);
    assert.notEqual(await git(root, "status", "--porcelain"), "", "the user's edit is left exactly as it was");

    // 6. An existing fix branch is not silently reused or overwritten.
    await git(root, "checkout", "--quiet", "--", "src/api.js");
    state = await session(root);
    const again = await cli(root, ["fix", dependency.id]);
    assert.equal(again.code, 1);
    assert.match(again.body.error.message, /already fixed and verified/);

    const branches = (await git(root, "branch", "--format=%(refname:short)")).split("\n").sort();
    assert.deepEqual(branches, ["main", `myrqen/fix-${dependency.id}`, `myrqen/fix-${injection.id}`, `myrqen/fix-${traversal.id}`].sort());
    assert.equal(await git(root, "remote"), "", "nothing was pushed anywhere");
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("fix refuses outside a git repository and explains the alternative", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-nogit-"));
  try {
    await fs.writeFile(path.join(root, "package.json"), JSON.stringify({ name: "x", type: "module", dependencies: { lodash: "4.17.11" } }));
    await cli(root, ["auto", "--sync", "no"]);
    const result = await cli(root, ["fix", "MYR-001"]);
    assert.equal(result.code, 1);
    assert.match(result.body.error.message, /not a git repository/);
    assert.match(result.body.error.message, /fix prompt/);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});
