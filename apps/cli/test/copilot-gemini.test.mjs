/**
 * GitHub Copilot and Gemini CLI integrations.
 *
 * The two properties under test are the ones a user cannot verify for
 * themselves before saying yes: nothing they wrote is lost, and running `link`
 * twice is the same as running it once. Every test uses a temporary directory
 * as both the repository and the home directory, so nothing here can reach the
 * real machine.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

const ROOT = path.resolve(import.meta.dirname, "..", "..", "..");
const { copilotAdapter, geminiAdapter } = await import(
  pathToFileURL(path.join(ROOT, "apps", "cli", "dist-tsc", "integrations", "adapters", "copilot-gemini.js")).href
);
const { applyPlan } = await import(pathToFileURL(path.join(ROOT, "apps", "cli", "dist-tsc", "integrations", "apply.js")).href);

const COPILOT_PROJECT_FILE = path.join(".github", "instructions", "myrqen.instructions.md");

async function sandbox(env = {}) {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-agents-"));
  const repoRoot = path.join(base, "project");
  const home = path.join(base, "home");
  await fs.mkdir(repoRoot, { recursive: true });
  await fs.mkdir(home, { recursive: true });
  return { repoRoot, home, skillSource: "", platform: process.platform, env };
}

async function write(target, contents) {
  await fs.mkdir(path.dirname(target), { recursive: true });
  await fs.writeFile(target, contents, "utf8");
  return contents;
}

async function readOrNull(target) {
  return fs.readFile(target, "utf8").catch(() => null);
}

async function install(adapter, context, scope = "project") {
  const plan = await adapter.createInstallPlan(context, scope);
  const applied = await applyPlan(plan);
  assert.ok(applied.ok, `applying ${adapter.id} failed: ${JSON.stringify(applied.writes)}`);
  return plan;
}

/* -------------------------------------------------------------- GitHub Copilot */

test("Copilot: planning is pure and targets the per-topic instructions file", async () => {
  const context = await sandbox();
  const plan = await copilotAdapter.createInstallPlan(context, "project");

  assert.equal(plan.writes.length, 1, "one file, and it is Myrqen's own");
  const [entry] = plan.writes;
  assert.equal(entry.action, "create");
  assert.equal(entry.displayPath, ".github/instructions/myrqen.instructions.md");
  assert.match(entry.contents, /^---\nname: Myrqen/, "frontmatter is the first thing in the file");
  assert.match(entry.contents, /\napplyTo: '\*\*'\n/, "applyTo is what makes Copilot load the file at all");
  assert.match(entry.contents, /<!-- myrqen:start v/, "the managed marker is an HTML comment, never inside the frontmatter");
  assert.ok(entry.contents.indexOf("<!-- myrqen:start") > entry.contents.indexOf("---\n\n"), "the marker opens below the frontmatter");

  assert.equal(await readOrNull(path.join(context.repoRoot, COPILOT_PROJECT_FILE)), null, "planning wrote nothing");
});

test("Copilot: an existing copilot-instructions.md is left byte for byte", async () => {
  const context = await sandbox();
  const teamFile = path.join(context.repoRoot, ".github", "copilot-instructions.md");
  const original = await write(teamFile, "# House rules\r\n\r\nPrefer tabs.\r\n");

  const plan = await copilotAdapter.createInstallPlan(context, "project");
  assert.ok(
    plan.writes.every((entry) => entry.path !== teamFile),
    "the shared repository file is not a write target"
  );
  assert.ok(
    plan.notes.some((note) => note.includes(".github/copilot-instructions.md")),
    "the plan says so out loud"
  );

  await applyPlan(plan);
  assert.equal(await fs.readFile(teamFile, "utf8"), original, "including its CRLF line endings");
  await fs.access(path.join(context.repoRoot, COPILOT_PROJECT_FILE));
});

test("Copilot: a second plan on an unchanged install changes nothing", async () => {
  const context = await sandbox();
  await install(copilotAdapter, context);

  const second = await copilotAdapter.createInstallPlan(context, "project");
  assert.equal(second.writes[0].action, "unchanged");
  assert.equal(second.writes[0].contents, undefined, "an unchanged write carries no content");
});

test("Copilot: an instructions file Myrqen did not write is blocked, not overwritten", async () => {
  const context = await sandbox();
  const mine = await write(path.join(context.repoRoot, COPILOT_PROJECT_FILE), "---\napplyTo: '**'\n---\n\nMy own notes.\n");

  const plan = await copilotAdapter.createInstallPlan(context, "project");
  assert.equal(plan.writes[0].action, "blocked");
  assert.match(plan.writes[0].reason, /did not write it/);

  await applyPlan(plan);
  assert.equal(await fs.readFile(path.join(context.repoRoot, COPILOT_PROJECT_FILE), "utf8"), mine);
});

test("Copilot: uninstalling removes only Myrqen's file", async () => {
  const context = await sandbox();
  const teamFile = path.join(context.repoRoot, ".github", "copilot-instructions.md");
  const original = await write(teamFile, "# House rules\n");
  const workflow = await write(path.join(context.repoRoot, ".github", "workflows", "ci.yml"), "name: ci\n");

  await install(copilotAdapter, context);
  const plan = await copilotAdapter.createUninstallPlan(context, "project");
  assert.equal(plan.writes[0].action, "remove");
  const applied = await applyPlan(plan);
  assert.ok(applied.ok);

  assert.equal(await readOrNull(path.join(context.repoRoot, COPILOT_PROJECT_FILE)), null);
  assert.equal(await fs.readFile(teamFile, "utf8"), original);
  assert.equal(await fs.readFile(path.join(context.repoRoot, ".github", "workflows", "ci.yml"), "utf8"), workflow);
});

test("Copilot: the global scope follows COPILOT_HOME when it is set", async () => {
  const plain = await sandbox();
  const globalPlan = await copilotAdapter.createInstallPlan(plain, "global");
  assert.equal(globalPlan.writes[0].path, path.join(plain.home, ".copilot", "instructions", "myrqen.instructions.md"));

  const moved = await sandbox();
  moved.env = { COPILOT_HOME: path.join(moved.home, "elsewhere") };
  const movedPlan = await copilotAdapter.createInstallPlan(moved, "global");
  assert.equal(movedPlan.writes[0].path, path.join(moved.home, "elsewhere", "instructions", "myrqen.instructions.md"));

  const relative = await sandbox();
  relative.env = { COPILOT_HOME: "../wherever" };
  const relativePlan = await copilotAdapter.createInstallPlan(relative, "global");
  assert.equal(
    relativePlan.writes[0].path,
    path.join(relative.home, ".copilot", "instructions", "myrqen.instructions.md"),
    "a relative override is ignored rather than resolved against the working directory"
  );

  assert.deepEqual(copilotAdapter.supportedScopes(plain), ["project", "global"]);
});

/* ------------------------------------------------------------------- Gemini */

test("Gemini: an empty project gets a marked region in GEMINI.md", async () => {
  const context = await sandbox();
  const plan = await geminiAdapter.createInstallPlan(context, "project");

  assert.equal(plan.writes.length, 1);
  assert.equal(plan.writes[0].action, "create");
  assert.equal(plan.writes[0].displayPath, "GEMINI.md");
  assert.match(plan.writes[0].contents, /<!-- myrqen:start v/);
  assert.match(plan.writes[0].contents, /<!-- myrqen:end -->/);
  assert.doesNotMatch(plan.writes[0].contents, /^---\n/, "GEMINI.md takes no frontmatter");

  assert.equal(await readOrNull(path.join(context.repoRoot, "GEMINI.md")), null, "planning wrote nothing");

  await applyPlan(plan);
  const written = await fs.readFile(path.join(context.repoRoot, "GEMINI.md"), "utf8");
  assert.match(written, /myrqen auto/, "the pointer says how to start an assessment");
  assert.ok(written.length < 3000, "the pointer stays short: this file is sent with every prompt");
});

test("Gemini: an existing GEMINI.md keeps everything the user wrote", async () => {
  const context = await sandbox();
  const target = path.join(context.repoRoot, "GEMINI.md");
  await write(target, "# Project notes\n\nBuild with make.\n");

  const plan = await geminiAdapter.createInstallPlan(context, "project");
  assert.equal(plan.writes[0].action, "merge");
  assert.equal(plan.writes[0].preservesExistingContent, true);

  await applyPlan(plan);
  const merged = await fs.readFile(target, "utf8");
  assert.ok(merged.startsWith("# Project notes\n\nBuild with make."), "the user's text stays at the top");
  assert.match(merged, /<!-- myrqen:start v/);

  const second = await geminiAdapter.createInstallPlan(context, "project");
  assert.equal(second.writes[0].action, "unchanged", "a second run is a no-op");
});

test("Gemini: uninstalling leaves unrelated content intact", async () => {
  const context = await sandbox();
  const target = path.join(context.repoRoot, "GEMINI.md");
  await write(target, "# Project notes\n\nBuild with make.\n");
  await install(geminiAdapter, context);

  const plan = await geminiAdapter.createUninstallPlan(context, "project");
  assert.ok(plan.writes.some((entry) => entry.action === "remove"));
  assert.ok(await applyPlan(plan).then((applied) => applied.ok));

  const left = await fs.readFile(target, "utf8");
  assert.equal(left.trim(), "# Project notes\n\nBuild with make.".trim());
  assert.doesNotMatch(left, /myrqen:/);
});

test("Gemini: a file Myrqen created is deleted rather than left empty", async () => {
  const context = await sandbox();
  await install(geminiAdapter, context);
  await applyPlan(await geminiAdapter.createUninstallPlan(context, "project"));
  assert.equal(await readOrNull(path.join(context.repoRoot, "GEMINI.md")), null);
});

test("Gemini: a configured context filename is honoured, and nothing else is read from settings", async () => {
  const context = await sandbox();
  await write(
    path.join(context.repoRoot, ".gemini", "settings.json"),
    JSON.stringify({ security: { auth: { apiKey: "sk-do-not-leak-this" } }, context: { fileName: "CONTEXT.md" } })
  );

  const plan = await geminiAdapter.createInstallPlan(context, "project");
  assert.equal(plan.writes[0].displayPath, "CONTEXT.md");
  assert.ok(
    plan.notes.some((note) => note.includes("CONTEXT.md")),
    "the user is told the file went somewhere other than GEMINI.md"
  );

  const everythingPrinted = JSON.stringify(plan);
  assert.doesNotMatch(everythingPrinted, /sk-do-not-leak-this/, "no other settings value escapes the adapter");
});

test("Gemini: a context filename that escapes the project is refused", async () => {
  for (const configured of ["../../.ssh/authorized_keys", "../evil.md", "/etc/passwd", ".env", "notes.txt"]) {
    const context = await sandbox();
    await write(path.join(context.repoRoot, ".gemini", "settings.json"), JSON.stringify({ context: { fileName: configured } }));
    const plan = await geminiAdapter.createInstallPlan(context, "project");
    assert.equal(plan.writes[0].path, path.join(context.repoRoot, "GEMINI.md"), `refused: ${configured}`);
  }
});

test("Gemini: unparseable settings fall back to GEMINI.md without throwing", async () => {
  const context = await sandbox();
  await write(path.join(context.repoRoot, ".gemini", "settings.json"), "{ half written");
  const plan = await geminiAdapter.createInstallPlan(context, "project");
  assert.equal(plan.writes[0].path, path.join(context.repoRoot, "GEMINI.md"));
});

test("Gemini: the global scope is the documented ~/.gemini/GEMINI.md", async () => {
  const context = await sandbox();
  const plan = await geminiAdapter.createInstallPlan(context, "global");
  assert.equal(plan.writes[0].path, path.join(context.home, ".gemini", "GEMINI.md"));
  assert.equal(plan.writes[0].displayPath, "~/.gemini/GEMINI.md");
  assert.deepEqual(geminiAdapter.supportedScopes(context), ["project", "global"]);
});

/* ------------------------------------------------ installed() and validate() */

test("installs are reconstructed from the files themselves and report healthy", async () => {
  const context = await sandbox();
  await write(path.join(context.repoRoot, "GEMINI.md"), "# Project notes\n");
  await install(copilotAdapter, context);
  await install(geminiAdapter, context);

  const copilotInstalled = await copilotAdapter.installed(context);
  assert.equal(copilotInstalled.length, 1);
  assert.equal(copilotInstalled[0].scope, "project");
  assert.equal(copilotInstalled[0].sharedFile, false, "Myrqen owns that file outright");
  assert.equal((await copilotAdapter.validate(context, copilotInstalled[0])).health, "healthy");

  const geminiInstalled = await geminiAdapter.installed(context);
  assert.equal(geminiInstalled.length, 1);
  assert.equal(geminiInstalled[0].sharedFile, true, "GEMINI.md also holds the user's own notes");
  assert.equal((await geminiAdapter.validate(context, geminiInstalled[0])).health, "healthy");
});

test("a duplicated managed section is reported as conflicted, not silently merged", async () => {
  const context = await sandbox();
  await install(geminiAdapter, context);
  const target = path.join(context.repoRoot, "GEMINI.md");
  const body = await fs.readFile(target, "utf8");
  await fs.writeFile(target, `${body}\n${body}`, "utf8");

  const [integration] = await geminiAdapter.installed(context);
  const validation = await geminiAdapter.validate(context, integration);
  assert.equal(validation.health, "conflicted");
  assert.match(validation.remedy, /myrqen link/);

  const plan = await geminiAdapter.createInstallPlan(context, "project");
  assert.equal(plan.writes[0].action, "blocked", "a conflicted file is never rewritten on a guess");
});

test("nothing is reported as installed in a project that has none", async () => {
  const context = await sandbox();
  assert.deepEqual(await copilotAdapter.installed(context), []);
  assert.deepEqual(await geminiAdapter.installed(context), []);
});
