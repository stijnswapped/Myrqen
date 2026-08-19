/** Agent skill installation: correct locations, no silent overwrite, idempotent. */
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
const SKILL_SOURCE = path.join(ROOT, "packages", "skill", "myrqen");

async function tempHome() {
  return fs.mkdtemp(path.join(os.tmpdir(), "myrqen-install-"));
}

async function loadInstaller() {
  // The bundled CLI is the artifact under test, but the installer is also
  // exercised directly so behaviour can be asserted precisely.
  return import(path.join(ROOT, "apps", "cli", "dist-tsc", "install", "skill.js"));
}

test("the portable bundle ships with the built CLI", async () => {
  const { stdout } = await run(process.execPath, [CLI, "skill", "path"], {
    env: { ...process.env, MYRQEN_NO_COLOR: "1" }
  });
  const location = stdout.trim();
  await fs.access(path.join(location, "SKILL.md"));
  const body = await fs.readFile(path.join(location, "SKILL.md"), "utf8");
  assert.match(body, /^---\nname: myrqen\n/, "the frontmatter names the skill");
  assert.match(body, /\$ARGUMENTS/, "effort arrives through the documented argument placeholder");
  for (const reference of ["METHODOLOGY.md", "SAFETY.md", "FINDINGS.md", "CLI.md"]) {
    await fs.access(path.join(location, "references", reference));
  }
});

test("agent targets cover the documented locations for each supported agent", async () => {
  const { agentTargets } = await loadInstaller();
  const home = os.homedir();
  const targets = agentTargets("/tmp/example-repo");
  const directories = targets.map((target) => target.skillsDirectory);

  assert.ok(directories.includes(path.join(home, ".claude", "skills")), "Claude Code personal");
  assert.ok(directories.includes(path.join("/tmp/example-repo", ".claude", "skills")), "Claude Code project");
  assert.ok(directories.includes(path.join(home, ".codex", "skills")), "Codex CLI");
  assert.ok(directories.includes(path.join(home, ".config", "opencode", "skills")), "OpenCode");
  assert.ok(directories.includes(path.join(home, ".agents", "skills")), "portable location");

  const claude = targets.find((target) => target.id === "claude-code");
  assert.equal(claude.slashInvocation, true, "Claude Code exposes the skill as a slash command");
});

test("installing writes the bundle and is a no-op when nothing changed", async () => {
  const { installSkill } = await loadInstaller();
  const home = await tempHome();
  const target = {
    id: "portable",
    label: "test",
    skillsDirectory: path.join(home, "skills"),
    scope: "personal",
    detectPaths: [],
    slashInvocation: false
  };

  const first = await installSkill(target, SKILL_SOURCE);
  assert.equal(first.action, "installed");
  assert.ok(first.fileCount >= 5);
  await fs.access(path.join(first.location, "SKILL.md"));
  await fs.access(path.join(first.location, ".myrqen-managed.json"));

  const second = await installSkill(target, SKILL_SOURCE);
  assert.equal(second.action, "unchanged", "a reinstall of the same bundle changes nothing");
});

test("a directory Myrqen did not write is backed up, never overwritten", async () => {
  const { installSkill } = await loadInstaller();
  const home = await tempHome();
  const target = {
    id: "portable",
    label: "test",
    skillsDirectory: path.join(home, "skills"),
    scope: "personal",
    detectPaths: [],
    slashInvocation: false
  };

  const destination = path.join(target.skillsDirectory, "myrqen");
  await fs.mkdir(destination, { recursive: true });
  await fs.writeFile(path.join(destination, "SKILL.md"), "# my own skill\n");

  const result = await installSkill(target, SKILL_SOURCE);
  assert.equal(result.action, "backed_up_and_installed");
  assert.ok(result.backupLocation);
  const preserved = await fs.readFile(path.join(result.backupLocation, "SKILL.md"), "utf8");
  assert.equal(preserved, "# my own skill\n", "the user's file is preserved verbatim");
});

test("an out-of-date managed install is updated in place", async () => {
  const { installSkill } = await loadInstaller();
  const home = await tempHome();
  const target = {
    id: "portable",
    label: "test",
    skillsDirectory: path.join(home, "skills"),
    scope: "personal",
    detectPaths: [],
    slashInvocation: false
  };

  const first = await installSkill(target, SKILL_SOURCE);
  await fs.writeFile(path.join(first.location, "SKILL.md"), "# stale copy\n");

  const second = await installSkill(target, SKILL_SOURCE);
  assert.equal(second.action, "updated");
  const body = await fs.readFile(path.join(second.location, "SKILL.md"), "utf8");
  assert.match(body, /Myrqen application security assessment/);
});
