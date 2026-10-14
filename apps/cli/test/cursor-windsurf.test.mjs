/** Cursor and Windsurf rule files: correct format, never clobbered, idempotent. */
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

const ROOT = path.resolve(import.meta.dirname, "..", "..", "..");
const DIST = path.join(ROOT, "apps", "cli", "dist-tsc");

async function loadAdapters() {
  return import(pathToFileURL(path.join(DIST, "integrations", "adapters", "cursor-windsurf.js")).href);
}

async function loadApplier() {
  return import(pathToFileURL(path.join(DIST, "integrations", "apply.js")).href);
}

/**
 * A temporary directory stands in for both the repository and the home
 * directory, so nothing in this file can reach the machine it runs on.
 */
async function fixture() {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-editor-rules-"));
  const repoRoot = path.join(base, "project");
  const home = path.join(base, "home");
  await fs.mkdir(repoRoot, { recursive: true });
  await fs.mkdir(home, { recursive: true });
  return { repoRoot, home, skillSource: "", platform: process.platform, env: {} };
}

async function install(adapter, context, scope) {
  const { applyPlan } = await loadApplier();
  const plan = await adapter.createInstallPlan(context, scope);
  const applied = await applyPlan(plan);
  assert.ok(applied.ok, "the plan applied cleanly");
  return plan;
}

async function exists(target) {
  try {
    await fs.access(target);
    return true;
  } catch {
    return false;
  }
}

test("Cursor supports only the scope Cursor documents", async () => {
  const { cursorAdapter } = await loadAdapters();
  const context = await fixture();

  assert.deepEqual(cursorAdapter.supportedScopes(context), ["project"]);
  assert.equal(cursorAdapter.id, "cursor");
  assert.match(cursorAdapter.documentation, /^https:\/\/cursor\.com\/docs\//);

  // Asking for global scope produces a plan that explains itself and writes
  // nothing, rather than inventing a path Cursor does not document.
  const plan = await cursorAdapter.createInstallPlan(context, "global");
  assert.deepEqual(plan.writes, []);
  assert.ok(plan.notes.some((note) => /user rules/i.test(note)));
});

test("Cursor gets an .mdc rule that loads on demand, and planning writes nothing", async () => {
  const { cursorAdapter } = await loadAdapters();
  const context = await fixture();

  const plan = await cursorAdapter.createInstallPlan(context, "project");
  assert.equal(plan.writes.length, 1);
  const [write] = plan.writes;
  assert.equal(write.action, "create");
  assert.equal(write.displayPath, ".cursor/rules/myrqen.mdc");
  assert.equal(await exists(write.path), false, "createInstallPlan is pure and applies nothing");

  // The extension and the frontmatter are what make Cursor read the file at
  // all; the markers must come after the YAML, never before it.
  assert.ok(write.contents.startsWith("---\n"), "frontmatter is the first byte of the file");
  assert.match(write.contents, /\nalwaysApply: false\n/, "the rule is not always on");
  assert.doesNotMatch(write.contents, /\nglobs:/, "no glob attaches the rule to unrelated edits");
  assert.match(write.contents, /<!-- myrqen:start v\d+ -->/);
  assert.match(write.contents, /<!-- myrqen:end -->/);
  assert.doesNotMatch(write.contents.split("---\n")[1], /<!--/, "no HTML comment inside the YAML block");

  // The pointer, not the method: a persistent rule file is read on every
  // conversation in the project, so a long payload here is a permanent tax.
  assert.ok(write.contents.split("\n").length < 60, "the payload stays a pointer");
});

test("Cursor leaves other rule files in .cursor/rules alone, and uninstall keeps them", async () => {
  const { cursorAdapter } = await loadAdapters();
  const context = await fixture();
  const { applyPlan } = await loadApplier();

  const teamRule = path.join(context.repoRoot, ".cursor", "rules", "team-conventions.mdc");
  const teamBody = "---\ndescription: house style\nalwaysApply: true\n---\n\nUse tabs.\n";
  await fs.mkdir(path.dirname(teamRule), { recursive: true });
  await fs.writeFile(teamRule, teamBody);

  await install(cursorAdapter, context, "project");
  assert.equal(await fs.readFile(teamRule, "utf8"), teamBody, "the team's rule is untouched");

  const removal = await cursorAdapter.createUninstallPlan(context, "project");
  assert.equal(removal.writes[0].action, "remove");
  assert.ok((await applyPlan(removal)).ok);

  assert.equal(await fs.readFile(teamRule, "utf8"), teamBody, "uninstall keeps unrelated rules");
  assert.equal(
    await exists(path.join(context.repoRoot, ".cursor", "rules", "myrqen.mdc")),
    false,
    "only Myrqen's own file is removed"
  );
});

test("a rule file Myrqen did not write is blocked, never overwritten", async () => {
  const { cursorAdapter } = await loadAdapters();
  const context = await fixture();

  const target = path.join(context.repoRoot, ".cursor", "rules", "myrqen.mdc");
  await fs.mkdir(path.dirname(target), { recursive: true });
  await fs.writeFile(target, "---\ndescription: mine\n---\n\nMy own notes.\n");

  const plan = await cursorAdapter.createInstallPlan(context, "project");
  assert.equal(plan.writes[0].action, "blocked");
  assert.ok(plan.writes[0].reason);
  assert.equal(plan.writes[0].contents, undefined);

  const removal = await cursorAdapter.createUninstallPlan(context, "project");
  assert.equal(removal.writes[0].action, "blocked", "unlink will not delete a file Myrqen does not own");
  assert.equal(await fs.readFile(target, "utf8"), "---\ndescription: mine\n---\n\nMy own notes.\n");
});

test("a second Cursor install changes nothing", async () => {
  const { cursorAdapter } = await loadAdapters();
  const context = await fixture();

  await install(cursorAdapter, context, "project");
  const target = path.join(context.repoRoot, ".cursor", "rules", "myrqen.mdc");
  const first = await fs.readFile(target, "utf8");

  const second = await cursorAdapter.createInstallPlan(context, "project");
  assert.equal(second.writes[0].action, "unchanged");
  assert.equal(second.writes[0].contents, undefined);
  assert.equal(await fs.readFile(target, "utf8"), first);

  const installed = await cursorAdapter.installed(context);
  assert.equal(installed.length, 1);
  assert.equal(installed[0].scope, "project");
  assert.equal(installed[0].sharedFile, false);
  assert.equal((await cursorAdapter.validate(context, installed[0])).health, "healthy");
});

test("Windsurf writes a model_decision rule for the project and merges the shared global file", async () => {
  const { windsurfAdapter } = await loadAdapters();
  const context = await fixture();

  assert.deepEqual(windsurfAdapter.supportedScopes(context), ["project", "global"]);

  const projectPlan = await windsurfAdapter.createInstallPlan(context, "project");
  assert.equal(projectPlan.writes[0].displayPath, ".windsurf/rules/myrqen.md");
  assert.ok(projectPlan.writes[0].contents.startsWith("---\n"));
  assert.match(projectPlan.writes[0].contents, /\ntrigger: model_decision\n/);
  assert.equal(projectPlan.writes[0].preservesExistingContent, false);

  const globalPlan = await windsurfAdapter.createInstallPlan(context, "global");
  assert.equal(globalPlan.writes[0].displayPath, "~/.codeium/windsurf/memories/global_rules.md");
});

test("Windsurf global rules keep the user's own rules byte for byte", async () => {
  const { windsurfAdapter } = await loadAdapters();
  const { applyPlan } = await loadApplier();
  const context = await fixture();

  const globalRules = path.join(context.home, ".codeium", "windsurf", "memories", "global_rules.md");
  const mine = "# My rules\n\nAlways answer in Dutch.\n";
  await fs.mkdir(path.dirname(globalRules), { recursive: true });
  await fs.writeFile(globalRules, mine);

  const plan = await install(windsurfAdapter, context, "global");
  assert.equal(plan.writes[0].action, "merge");
  assert.equal(plan.writes[0].preservesExistingContent, true);

  const merged = await fs.readFile(globalRules, "utf8");
  assert.ok(merged.startsWith(mine.trimEnd()), "the user's rules stay at the top, unmodified");
  assert.match(merged, /<!-- myrqen:start v\d+ -->/);

  const second = await windsurfAdapter.createInstallPlan(context, "global");
  assert.equal(second.writes[0].action, "unchanged", "a second run is a no-op");

  const installed = await windsurfAdapter.installed(context);
  const global = installed.find((entry) => entry.scope === "global");
  assert.equal(global.sharedFile, true);
  assert.equal((await windsurfAdapter.validate(context, global)).health, "healthy");

  const removal = await windsurfAdapter.createUninstallPlan(context, "global");
  assert.equal(removal.writes[0].action, "remove");
  assert.ok((await applyPlan(removal)).ok);
  const afterRemoval = await fs.readFile(globalRules, "utf8");
  assert.equal(afterRemoval.trimEnd(), mine.trimEnd(), "the user's rules survive unlink verbatim");
  assert.doesNotMatch(afterRemoval, /myrqen:/, "no marker is left behind");
});

test("Windsurf project rule installs, repeats cleanly, and uninstalls without taking the directory's other rules", async () => {
  const { windsurfAdapter } = await loadAdapters();
  const { applyPlan } = await loadApplier();
  const context = await fixture();

  const otherRule = path.join(context.repoRoot, ".windsurf", "rules", "style.md");
  const otherBody = "---\ntrigger: always_on\n---\n\nPrefer small files.\n";
  await fs.mkdir(path.dirname(otherRule), { recursive: true });
  await fs.writeFile(otherRule, otherBody);

  await install(windsurfAdapter, context, "project");
  const second = await windsurfAdapter.createInstallPlan(context, "project");
  assert.equal(second.writes[0].action, "unchanged");

  const removal = await windsurfAdapter.createUninstallPlan(context, "project");
  assert.ok((await applyPlan(removal)).ok);

  assert.equal(await fs.readFile(otherRule, "utf8"), otherBody);
  assert.equal(await exists(path.join(context.repoRoot, ".windsurf", "rules", "myrqen.md")), false);
});

test("uninstalling something that was never installed is a no-op, not an error", async () => {
  const { cursorAdapter, windsurfAdapter } = await loadAdapters();
  const context = await fixture();

  for (const [adapter, scope] of [
    [cursorAdapter, "project"],
    [windsurfAdapter, "project"],
    [windsurfAdapter, "global"]
  ]) {
    const plan = await adapter.createUninstallPlan(context, scope);
    assert.deepEqual(plan.writes, [], `${adapter.id}/${scope} has nothing to remove`);
  }
});

test("a stale payload version is reported as stale, and a duplicated region as conflicted", async () => {
  const { cursorAdapter } = await loadAdapters();
  const context = await fixture();

  await install(cursorAdapter, context, "project");
  const target = path.join(context.repoRoot, ".cursor", "rules", "myrqen.mdc");
  const current = await fs.readFile(target, "utf8");
  const [installed] = await cursorAdapter.installed(context);

  await fs.writeFile(target, current.replace(/myrqen:start v\d+/, "myrqen:start v0"));
  assert.equal((await cursorAdapter.validate(context, installed)).health, "stale");

  await fs.writeFile(target, `${current}\n${current.slice(current.indexOf("<!-- myrqen:start"))}`);
  assert.equal((await cursorAdapter.validate(context, installed)).health, "conflicted");

  await fs.rm(target);
  assert.equal((await cursorAdapter.validate(context, installed)).health, "missing");
});

test("the Cursor pointer names the slash command only when a skill is actually there", async () => {
  const { cursorAdapter } = await loadAdapters();
  const withoutSkill = await fixture();

  const plain = await cursorAdapter.createInstallPlan(withoutSkill, "project");
  assert.doesNotMatch(plain.writes[0].contents, /\/myrqen`/, "no slash command is advertised without a skill");
  assert.match(plain.writes[0].contents, /`myrqen auto`/);

  // Cursor reads .claude/skills for compatibility, so a Claude Code install in
  // the same project is what makes /myrqen answer.
  const withSkill = await fixture();
  await fs.mkdir(path.join(withSkill.repoRoot, ".claude", "skills", "myrqen"), { recursive: true });
  const pointed = await cursorAdapter.createInstallPlan(withSkill, "project");
  assert.match(pointed.writes[0].contents, /`\/myrqen`/);
  assert.ok(pointed.notes.some((note) => note.includes("/myrqen")));
});
