/** Claude Code and shared AGENTS.md adapters: correct paths, no clobbering, idempotent. */
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

const ROOT = path.resolve(import.meta.dirname, "..", "..", "..");
const DIST = path.join(ROOT, "apps", "cli", "dist-tsc");
const SKILL_SOURCE = path.join(ROOT, "packages", "skill", "myrqen");

const { claudeCodeAdapter, agentsMdAdapter } = await import(pathToFileURL(path.join(DIST, "integrations", "adapters", "claude.js")).href);
const { applyPlan } = await import(pathToFileURL(path.join(DIST, "integrations", "apply.js")).href);

/**
 * A whole machine in a temp directory. Home and repository root are separate
 * trees under it so a global-scope write that leaked into the project (or the
 * other way round) shows up as a missing file rather than passing quietly.
 */
async function fixture(env = {}) {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-adapter-"));
  const home = path.join(base, "home");
  const repoRoot = path.join(base, "repo");
  await fs.mkdir(home, { recursive: true });
  await fs.mkdir(repoRoot, { recursive: true });
  return {
    base,
    home,
    repoRoot,
    context: { repoRoot, home, skillSource: SKILL_SOURCE, platform: process.platform, env }
  };
}

async function read(target) {
  return fs.readFile(target, "utf8").catch(() => null);
}

async function exists(target) {
  return fs.access(target).then(
    () => true,
    () => false
  );
}

function actionFor(plan, displayPath) {
  return plan.writes.find((write) => write.displayPath === displayPath)?.action;
}

async function install(adapter, context, scope) {
  const plan = await adapter.createInstallPlan(context, scope);
  const applied = await applyPlan(plan);
  assert.ok(applied.ok, `${adapter.id} ${scope} plan applied cleanly`);
  return plan;
}

/* ---------- Claude Code ---------- */

test("claude-code plans the documented locations and writes nothing while planning", async () => {
  const { context, repoRoot } = await fixture();

  assert.deepEqual(claudeCodeAdapter.supportedScopes(context), ["project", "global"]);

  const plan = await claudeCodeAdapter.createInstallPlan(context, "project");
  const paths = plan.writes.map((write) => write.displayPath);
  assert.ok(paths.includes(".claude/skills/myrqen/SKILL.md"), "the skill bundle lands in .claude/skills");
  assert.ok(paths.includes(".claude/skills/myrqen/references/METHODOLOGY.md"), "reference files are planned too");
  assert.ok(paths.includes("CLAUDE.md"), "the pointer goes to the project's CLAUDE.md");
  assert.ok(
    plan.writes.every((write) => write.action !== "blocked"),
    "an empty project blocks nothing"
  );

  // Planning is pure. Nothing above may exist yet.
  assert.equal(await exists(path.join(repoRoot, ".claude")), false, "planning created no skill directory");
  assert.equal(await exists(path.join(repoRoot, "CLAUDE.md")), false, "planning created no CLAUDE.md");
});

test("claude-code installs the full method as a skill and only a pointer in CLAUDE.md", async () => {
  const { context, repoRoot } = await fixture();
  await install(claudeCodeAdapter, context, "project");

  const skill = await read(path.join(repoRoot, ".claude", "skills", "myrqen", "SKILL.md"));
  assert.match(skill, /^---\nname: myrqen\n/, "the portable bundle is installed verbatim");
  assert.ok(await exists(path.join(repoRoot, ".claude", "skills", "myrqen", ".myrqen-managed.json")));

  const pointer = await read(path.join(repoRoot, "CLAUDE.md"));
  assert.match(pointer, /<!-- myrqen:start v\d+ -->/, "the region is fenced with HTML comments, valid in Markdown");
  assert.match(pointer, /<!-- myrqen:end -->/);
  assert.match(pointer, /\/myrqen/, "the pointer names the slash invocation Claude Code supports");
  assert.ok(
    pointer.split("\n").length < 45,
    "the always-on file gets a pointer, not the method (was " + pointer.split("\n").length + " lines)"
  );
  assert.ok(!pointer.includes("## Phase"), "no methodology leaked into the always-on file");
});

test("claude-code keeps an existing CLAUDE.md byte for byte", async () => {
  const { context, repoRoot } = await fixture();
  const original = "# House rules\n\nAlways use tabs.\nNever touch `legacy/`.\n";
  await fs.writeFile(path.join(repoRoot, "CLAUDE.md"), original);

  const plan = await install(claudeCodeAdapter, context, "project");
  assert.equal(actionFor(plan, "CLAUDE.md"), "merge");
  assert.equal(
    plan.writes.find((write) => write.displayPath === "CLAUDE.md").preservesExistingContent,
    true,
    "the plan tells the user their content is preserved before they answer"
  );

  const after = await read(path.join(repoRoot, "CLAUDE.md"));
  assert.ok(after.startsWith(original.trimEnd()), "the user's instructions stay first and unmodified");
  assert.match(after, /Always use tabs\./);
  assert.match(after, /Never touch `legacy\/`\./);
});

test("claude-code prefers the CLAUDE.md the project already keeps under .claude", async () => {
  const { context, repoRoot } = await fixture();
  await fs.mkdir(path.join(repoRoot, ".claude"), { recursive: true });
  await fs.writeFile(path.join(repoRoot, ".claude", "CLAUDE.md"), "# Team notes\n");

  await install(claudeCodeAdapter, context, "project");

  assert.match(await read(path.join(repoRoot, ".claude", "CLAUDE.md")), /myrqen:start/);
  assert.equal(await exists(path.join(repoRoot, "CLAUDE.md")), false, "a second instruction file is not invented");
});

test("claude-code is idempotent: a second plan changes nothing", async () => {
  const { context } = await fixture();
  await install(claudeCodeAdapter, context, "project");

  const second = await claudeCodeAdapter.createInstallPlan(context, "project");
  for (const write of second.writes) {
    assert.equal(write.action, "unchanged", `${write.displayPath} is already correct`);
    assert.equal(write.contents, undefined, "an unchanged write carries no content");
  }
});

test("claude-code global scope uses the documented user directory, and CLAUDE_CONFIG_DIR when set", async () => {
  const plain = await fixture();
  await install(claudeCodeAdapter, plain.context, "global");
  assert.ok(await exists(path.join(plain.home, ".claude", "skills", "myrqen", "SKILL.md")));
  assert.match(await read(path.join(plain.home, ".claude", "CLAUDE.md")), /myrqen:start/);

  const relocated = await fixture();
  const configDirectory = path.join(relocated.base, "elsewhere");
  relocated.context.env = { CLAUDE_CONFIG_DIR: configDirectory };
  await install(claudeCodeAdapter, relocated.context, "global");
  assert.ok(
    await exists(path.join(configDirectory, "skills", "myrqen", "SKILL.md")),
    "an overridden configuration directory is honoured, or the skill installs where Claude never looks"
  );
  assert.equal(await exists(path.join(relocated.home, ".claude")), false);
});

test("claude-code refuses to overwrite a skill directory it did not write", async () => {
  const { context, repoRoot } = await fixture();
  const foreign = path.join(repoRoot, ".claude", "skills", "myrqen");
  await fs.mkdir(foreign, { recursive: true });
  await fs.writeFile(path.join(foreign, "SKILL.md"), "# my own skill\n");

  const plan = await claudeCodeAdapter.createInstallPlan(context, "project");
  const blocked = plan.writes.find((write) => write.action === "blocked");
  assert.ok(blocked, "the conflicting directory blocks the skill write");
  assert.match(blocked.reason, /did not write/);

  await applyPlan(plan);
  assert.equal(await read(path.join(foreign, "SKILL.md")), "# my own skill\n", "the user's skill is untouched");
});

test("claude-code reports what is installed and validates it", async () => {
  const { context } = await fixture();
  assert.deepEqual(await claudeCodeAdapter.installed(context), []);

  await install(claudeCodeAdapter, context, "project");
  const installed = await claudeCodeAdapter.installed(context);
  assert.equal(installed.length, 1);
  assert.equal(installed[0].scope, "project");
  assert.equal(installed[0].displayPath, "CLAUDE.md");
  assert.equal(installed[0].sharedFile, false, "a CLAUDE.md Myrqen created holds nothing else");

  assert.equal((await claudeCodeAdapter.validate(context, installed[0])).health, "healthy");

  await fs.writeFile(path.join(context.repoRoot, "CLAUDE.md"), "# only mine\n");
  const stale = await claudeCodeAdapter.validate(context, installed[0]);
  assert.equal(stale.health, "stale");
  assert.match(stale.remedy, /myrqen link/);
});

test("claude-code uninstall removes its own files and leaves everything else alone", async () => {
  const { context, repoRoot } = await fixture();
  await fs.writeFile(path.join(repoRoot, "CLAUDE.md"), "# House rules\n\nAlways use tabs.\n");
  const ownSkill = path.join(repoRoot, ".claude", "skills", "review-checklist");
  await fs.mkdir(ownSkill, { recursive: true });
  await fs.writeFile(path.join(ownSkill, "SKILL.md"), "# mine\n");

  await install(claudeCodeAdapter, context, "project");

  const plan = await claudeCodeAdapter.createUninstallPlan(context, "project");
  assert.ok(
    plan.writes.every((write) => write.action === "remove"),
    "an uninstall plan only removes"
  );
  const applied = await applyPlan(plan);
  assert.ok(applied.ok);

  assert.equal(await exists(path.join(repoRoot, ".claude", "skills", "myrqen")), false, "the skill directory is gone");
  assert.equal(await read(path.join(ownSkill, "SKILL.md")), "# mine\n", "the user's other skill survives");

  const after = await read(path.join(repoRoot, "CLAUDE.md"));
  assert.equal(after.trim(), "# House rules\n\nAlways use tabs.".trim(), "CLAUDE.md is back to the user's own content");
  assert.deepEqual(await claudeCodeAdapter.installed(context), []);
});

test("claude-code uninstall deletes a CLAUDE.md that held nothing but the managed region", async () => {
  const { context, repoRoot } = await fixture();
  await install(claudeCodeAdapter, context, "project");
  await applyPlan(await claudeCodeAdapter.createUninstallPlan(context, "project"));
  assert.equal(await exists(path.join(repoRoot, "CLAUDE.md")), false, "a file Myrqen created is not left behind empty");
});

test("claude-code detection reads existence, never contents", async () => {
  const { context, repoRoot } = await fixture();
  const empty = await claudeCodeAdapter.detect(context);
  assert.ok(
    !empty.signals.some((signal) => signal.kind === "project_config"),
    "an unconfigured project produces no project signal"
  );

  await fs.mkdir(path.join(repoRoot, ".claude"), { recursive: true });
  const configured = await claudeCodeAdapter.detect(context);
  const project = configured.signals.find((signal) => signal.kind === "project_config");
  assert.ok(project, "a project .claude directory is a signal");
  assert.equal(project.detail, ".claude");
});

test("the skill bundle lands in the documented project directory and nowhere else", async () => {
  // This used to assert that the adapter and a second, imperative installer
  // agreed on the destination. That installer is gone — one code path plans a
  // skill directory now — so what is left to protect is the destination itself:
  // Claude Code reads `.claude/skills/<name>/`, and a bundle one level off is
  // an install that looks fine and does nothing.
  const { context, repoRoot } = await fixture();
  const plan = await claudeCodeAdapter.createInstallPlan(context, "project");
  const skillWrite = plan.writes.find((write) => write.path.endsWith(path.join("myrqen", "SKILL.md")));
  assert.equal(path.dirname(skillWrite.path), path.join(repoRoot, ".claude", "skills", "myrqen"));
  assert.ok(
    plan.writes.some((write) => write.path === path.join(repoRoot, ".claude", "skills", "myrqen", ".myrqen-managed.json")),
    "the managed marker is planned beside the bundle, so a later run recognises its own work"
  );
});

/* ---------- shared AGENTS.md ---------- */

test("agents-md is honest about being a convention rather than a program", async () => {
  const { context, repoRoot } = await fixture();

  const nothing = await agentsMdAdapter.detect(context);
  assert.equal(nothing.confidence, "absent");
  assert.equal(nothing.detected, false);

  await fs.writeFile(path.join(repoRoot, "AGENTS.md"), "# Build\n\nnpm test\n");
  const present = await agentsMdAdapter.detect(context);
  assert.equal(present.confidence, "project_only", "the file proves the repository, not the machine");

  assert.deepEqual(agentsMdAdapter.supportedScopes(context), ["project"], "no user-level location is documented");
});

test("agents-md merges into an existing AGENTS.md and is idempotent", async () => {
  const { context, repoRoot } = await fixture();
  const original = "# Example\n\n## Build\n\n`npm run build`\n";
  await fs.writeFile(path.join(repoRoot, "AGENTS.md"), original);

  const plan = await install(agentsMdAdapter, context, "project");
  assert.equal(actionFor(plan, "AGENTS.md"), "merge");

  const after = await read(path.join(repoRoot, "AGENTS.md"));
  assert.ok(after.startsWith(original.trimEnd()), "the project's own instructions are preserved");
  assert.match(after, /<!-- myrqen:start v\d+ -->/);
  assert.ok(!after.includes("/myrqen"), "no single agent's slash syntax is claimed for a shared file");
  assert.match(after, /myrqen auto/, "the universal CLI invocation is what a shared file can promise");

  const second = await agentsMdAdapter.createInstallPlan(context, "project");
  assert.equal(actionFor(second, "AGENTS.md"), "unchanged");
});

test("agents-md creates the file when the project has none", async () => {
  const { context, repoRoot } = await fixture();
  const plan = await install(agentsMdAdapter, context, "project");
  assert.equal(actionFor(plan, "AGENTS.md"), "create");
  assert.match(await read(path.join(repoRoot, "AGENTS.md")), /Myrqen — security assessment/);

  const installed = await agentsMdAdapter.installed(context);
  assert.equal(installed.length, 1);
  assert.equal(installed[0].sharedFile, false);
  assert.equal((await agentsMdAdapter.validate(context, installed[0])).health, "healthy");
});

test("agents-md global scope is blocked rather than guessed at", async () => {
  const { context, home } = await fixture();
  const plan = await agentsMdAdapter.createInstallPlan(context, "global");
  assert.equal(plan.writes.length, 1);
  assert.equal(plan.writes[0].action, "blocked");
  assert.match(plan.writes[0].reason, /no user-level location/);

  await applyPlan(plan);
  assert.equal(await exists(path.join(home, "AGENTS.md")), false, "nothing is written outside the documented location");
});

test("agents-md uninstall leaves unrelated content intact", async () => {
  const { context, repoRoot } = await fixture();
  const original = "# Example\n\n## Testing\n\nRun `npm test` before every commit.\n";
  await fs.writeFile(path.join(repoRoot, "AGENTS.md"), original);
  await install(agentsMdAdapter, context, "project");

  const applied = await applyPlan(await agentsMdAdapter.createUninstallPlan(context, "project"));
  assert.ok(applied.ok);

  const after = await read(path.join(repoRoot, "AGENTS.md"));
  assert.equal(after.trim(), original.trim(), "the file is exactly what the project had before");
  assert.deepEqual(await agentsMdAdapter.installed(context), []);
});
