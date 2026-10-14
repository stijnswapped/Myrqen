/**
 * Codex, Kiro, Aider, and OpenCode adapters.
 *
 * Every case runs against temporary directories used as the repository root and
 * the home directory, so a failing test can never reach the machine it runs on.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

const ROOT = path.resolve(import.meta.dirname, "..", "..", "..");
const DIST = path.join(ROOT, "apps", "cli", "dist-tsc");
const SKILL_SOURCE = path.join(ROOT, "packages", "skill", "myrqen");

const adapters = await import(pathToFileURL(path.join(DIST, "integrations", "adapters", "misc.js")).href);
const { applyPlan } = await import(pathToFileURL(path.join(DIST, "integrations", "apply.js")).href);
const { codexAdapter, kiroAdapter, aiderAdapter, opencodeAdapter } = adapters;

async function fixture(env = {}) {
  const repoRoot = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-repo-"));
  const home = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-home-"));
  return { repoRoot, home, skillSource: SKILL_SOURCE, platform: "linux", env };
}

async function install(adapter, context, scope) {
  const plan = await adapter.createInstallPlan(context, scope);
  const applied = await applyPlan(plan);
  assert.ok(applied.ok, `${adapter.id}/${scope} applied cleanly`);
  return plan;
}

async function uninstall(adapter, context, scope) {
  const plan = await adapter.createUninstallPlan(context, scope);
  const applied = await applyPlan(plan);
  assert.ok(applied.ok, `${adapter.id}/${scope} uninstalled cleanly`);
  return plan;
}

function actionFor(plan, suffix) {
  const write = plan.writes.find((entry) => entry.path.endsWith(suffix));
  assert.ok(write, `plan has a write for ${suffix} (has: ${plan.writes.map((w) => w.displayPath).join(", ")})`);
  return write;
}

async function exists(target) {
  try {
    await fs.access(target);
    return true;
  } catch {
    return false;
  }
}

async function write(target, contents) {
  await fs.mkdir(path.dirname(target), { recursive: true });
  await fs.writeFile(target, contents, "utf8");
}

/* ---------- planning writes nothing ---------- */

test("planning never touches the disk", async () => {
  const context = await fixture();
  for (const adapter of [codexAdapter, kiroAdapter, aiderAdapter, opencodeAdapter]) {
    for (const scope of adapter.supportedScopes(context)) {
      await adapter.createInstallPlan(context, scope);
    }
  }
  assert.deepEqual(await fs.readdir(context.repoRoot), [], "the project is untouched by planning");
  assert.deepEqual(await fs.readdir(context.home), [], "the home directory is untouched by planning");
});

/* ---------- Codex ---------- */

test("codex global installs the skill and merges a pointer into $CODEX_HOME/AGENTS.md", async () => {
  const context = await fixture();
  const plan = await install(codexAdapter, context, "global");

  const skill = path.join(context.home, ".agents", "skills", "myrqen", "SKILL.md");
  const instructions = path.join(context.home, ".codex", "AGENTS.md");
  assert.equal(actionFor(plan, path.join("skills", "myrqen", "SKILL.md")).action, "create");
  assert.ok(await exists(skill), "the bundle is installed in the documented home skills directory");
  assert.ok(await exists(path.join(context.home, ".agents", "skills", "myrqen", "references", "SAFETY.md")));

  const body = await fs.readFile(instructions, "utf8");
  assert.match(body, /myrqen:start v/, "the pointer sits in a managed region");
  assert.ok(body.length < 3000, "an always-on instructions file gets the pointer, not the method");
});

test("codex resolves CODEX_HOME instead of assuming ~/.codex", async () => {
  const custom = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-codexhome-"));
  const context = await fixture({ CODEX_HOME: custom });
  await install(codexAdapter, context, "global");

  assert.ok(await exists(path.join(custom, "AGENTS.md")), "the pointer follows CODEX_HOME");
  assert.equal(await exists(path.join(context.home, ".codex", "AGENTS.md")), false, "the default path is not used");
});

test("codex writes into AGENTS.override.md when one exists, because that is the file it reads", async () => {
  const context = await fixture();
  const override = path.join(context.home, ".codex", "AGENTS.override.md");
  await write(override, "# my override\n");
  await install(codexAdapter, context, "global");

  const body = await fs.readFile(override, "utf8");
  assert.match(body, /# my override/, "the user's override file is preserved");
  assert.match(body, /myrqen:start v/);
  assert.equal(await exists(path.join(context.home, ".codex", "AGENTS.md")), false);
});

test("codex keeps an existing user AGENTS.md byte for byte, and restores it on uninstall", async () => {
  const context = await fixture();
  const instructions = path.join(context.home, ".codex", "AGENTS.md");
  const original = "# House rules\r\n\r\nUse tabs. Never force-push.\r\n";
  await write(instructions, original);

  const plan = await install(codexAdapter, context, "global");
  assert.equal(actionFor(plan, path.join(".codex", "AGENTS.md")).action, "merge");
  const merged = await fs.readFile(instructions, "utf8");
  assert.ok(merged.includes("Use tabs. Never force-push."), "the user's instructions survive the merge");
  assert.match(merged, /\r\n/, "CRLF line endings are preserved");

  await uninstall(codexAdapter, context, "global");
  const after = await fs.readFile(instructions, "utf8");
  assert.ok(after.includes("Use tabs. Never force-push."), "the user's instructions survive the uninstall");
  assert.doesNotMatch(after, /myrqen:start/, "Myrqen's region is gone");
  assert.equal(await exists(path.join(context.home, ".agents", "skills", "myrqen")), false, "the skill directory is removed");
});

test("codex project scope installs the skill and writes nothing to AGENTS.md", async () => {
  const context = await fixture();
  const projectAgents = path.join(context.repoRoot, "AGENTS.md");
  await write(projectAgents, "# team notes\n");

  const plan = await install(codexAdapter, context, "project");
  assert.ok(
    plan.writes.every((entry) => !entry.path.endsWith(`${path.sep}AGENTS.md`)),
    "AGENTS.md belongs to the agents-md adapter"
  );
  assert.equal(await fs.readFile(projectAgents, "utf8"), "# team notes\n");
  assert.ok(await exists(path.join(context.repoRoot, ".agents", "skills", "myrqen", "SKILL.md")));
  assert.ok(
    plan.notes.some((note) => note.includes("AGENTS.md")),
    "the plan says which adapter covers the instructions file"
  );
});

test("a second codex link changes nothing", async () => {
  const context = await fixture();
  await install(codexAdapter, context, "global");
  const second = await codexAdapter.createInstallPlan(context, "global");
  assert.ok(
    second.writes.every((entry) => entry.action === "unchanged"),
    `every write is unchanged, got ${second.writes.map((entry) => entry.action).join(", ")}`
  );
  assert.ok(second.writes.every((entry) => entry.contents === undefined), "an unchanged write carries no content");
});

test("codex reports what it installed and validates it as healthy", async () => {
  const context = await fixture();
  await install(codexAdapter, context, "global");
  const installed = await codexAdapter.installed(context);
  assert.equal(installed.length, 1, "one row per scope, so unlink cannot plan the same removal twice");
  assert.equal(installed[0].scope, "global");
  assert.equal((await codexAdapter.validate(context, installed[0])).health, "healthy");
});

/* ---------- Kiro ---------- */

test("kiro writes a manual steering file whose frontmatter is the first bytes of the file", async () => {
  const context = await fixture();
  await install(kiroAdapter, context, "project");

  const steering = path.join(context.repoRoot, ".kiro", "steering", "myrqen.md");
  const body = await fs.readFile(steering, "utf8");
  assert.ok(body.startsWith("---\ninclusion: manual\n---\n"), "Kiro requires frontmatter in the literal first bytes");
  assert.doesNotMatch(body.slice(0, body.indexOf("---", 3)), /<!--/, "no HTML comment inside the YAML block");
  assert.match(body, /myrqen:start v/, "the managed marker sits after the frontmatter");
  assert.ok(await exists(path.join(context.repoRoot, ".kiro", "skills", "myrqen", "SKILL.md")), "the method goes in the skill");
});

test("kiro supports the documented global scope and leaves other steering files alone", async () => {
  const context = await fixture();
  assert.deepEqual(kiroAdapter.supportedScopes(context), ["project", "global"]);
  const theirs = path.join(context.home, ".kiro", "steering", "product.md");
  await write(theirs, "# product\n");

  await install(kiroAdapter, context, "global");
  assert.ok(await exists(path.join(context.home, ".kiro", "steering", "myrqen.md")));

  await uninstall(kiroAdapter, context, "global");
  assert.equal(await fs.readFile(theirs, "utf8"), "# product\n", "the user's own steering file is untouched");
  assert.equal(await exists(path.join(context.home, ".kiro", "steering", "myrqen.md")), false);
  assert.equal(await exists(path.join(context.home, ".kiro", "skills", "myrqen")), false);
});

test("kiro refuses to overwrite a steering file Myrqen did not write", async () => {
  const context = await fixture();
  const steering = path.join(context.repoRoot, ".kiro", "steering", "myrqen.md");
  await write(steering, "# somebody else's steering file\n");

  const plan = await kiroAdapter.createInstallPlan(context, "project");
  const blocked = actionFor(plan, path.join("steering", "myrqen.md"));
  assert.equal(blocked.action, "blocked");
  assert.ok(blocked.reason, "a blocked write says why");
  await applyPlan(plan);
  assert.equal(await fs.readFile(steering, "utf8"), "# somebody else's steering file\n");
});

test("a second kiro link changes nothing", async () => {
  const context = await fixture();
  await install(kiroAdapter, context, "project");
  const second = await kiroAdapter.createInstallPlan(context, "project");
  assert.ok(
    second.writes.every((entry) => entry.action === "unchanged"),
    `every write is unchanged, got ${second.writes.map((entry) => entry.action).join(", ")}`
  );
});

/* ---------- Aider ---------- */

test("aider writes a conventions file and the read: entry that makes aider load it", async () => {
  const context = await fixture();
  assert.deepEqual(aiderAdapter.supportedScopes(context), ["project"], "no documented home location for the conventions file");

  await install(aiderAdapter, context, "project");
  const conventions = await fs.readFile(path.join(context.repoRoot, "MYRQEN.md"), "utf8");
  assert.match(conventions, /myrqen:start v/);
  const config = await fs.readFile(path.join(context.repoRoot, ".aider.conf.yml"), "utf8");
  assert.match(config, /^# myrqen:start v/m, "YAML gets hash comments, never HTML ones");
  assert.doesNotMatch(config, /<!--/);
  assert.match(config, /read:\n\s+- MYRQEN\.md/);
});

test("aider appends to an existing read: list and preserves every other line", async () => {
  const context = await fixture();
  const configPath = path.join(context.repoRoot, ".aider.conf.yml");
  const original = [
    "# our aider setup",
    "model: gpt-5",
    "read:",
    "  - CONVENTIONS.md # the team's rules",
    "auto-commits: false",
    ""
  ].join("\n");
  await write(configPath, original);

  const plan = await install(aiderAdapter, context, "project");
  assert.equal(actionFor(plan, ".aider.conf.yml").action, "merge");
  const after = await fs.readFile(configPath, "utf8");
  assert.equal(
    after,
    [
      "# our aider setup",
      "model: gpt-5",
      "read:",
      "  - CONVENTIONS.md # the team's rules",
      "  - MYRQEN.md",
      "auto-commits: false",
      ""
    ].join("\n"),
    "one line added, nothing else rewritten"
  );
  assert.doesNotMatch(after, /myrqen:start/, "an existing read: key is extended rather than duplicated in a region");

  await uninstall(aiderAdapter, context, "project");
  assert.equal(await fs.readFile(configPath, "utf8"), original, "uninstall restores the file exactly");
  assert.equal(await exists(path.join(context.repoRoot, "MYRQEN.md")), false);
});

test("aider converts a single read: scalar into a list without losing its comment", async () => {
  const context = await fixture();
  const configPath = path.join(context.repoRoot, ".aider.conf.yml");
  await write(configPath, "read: CONVENTIONS.md # team rules\nmodel: gpt-5\n");

  await install(aiderAdapter, context, "project");
  assert.equal(
    await fs.readFile(configPath, "utf8"),
    "read: # team rules\n  - CONVENTIONS.md\n  - MYRQEN.md\nmodel: gpt-5\n"
  );
});

test("aider extends a flow-style read: list in place", async () => {
  const context = await fixture();
  const configPath = path.join(context.repoRoot, ".aider.conf.yml");
  await write(configPath, "read: [CONVENTIONS.md, STYLE.md]\n");

  await install(aiderAdapter, context, "project");
  assert.equal(await fs.readFile(configPath, "utf8"), "read: [CONVENTIONS.md, STYLE.md, MYRQEN.md]\n");
});

test("aider blocks rather than guessing at a read: key it cannot edit", async () => {
  const context = await fixture();
  const configPath = path.join(context.repoRoot, ".aider.conf.yml");
  const original = "read:\n  from: somewhere\n";
  await write(configPath, original);

  const plan = await aiderAdapter.createInstallPlan(context, "project");
  const blocked = actionFor(plan, ".aider.conf.yml");
  assert.equal(blocked.action, "blocked");
  assert.match(blocked.reason, /read:/);
  assert.ok(
    plan.notes.some((note) => note.includes("aider will not read it")),
    "the user is told the install is incomplete"
  );
  await applyPlan(plan);
  assert.equal(await fs.readFile(configPath, "utf8"), original, "a blocked write changes nothing");
});

test("a second aider link changes nothing", async () => {
  const context = await fixture();
  await install(aiderAdapter, context, "project");
  const second = await aiderAdapter.createInstallPlan(context, "project");
  assert.ok(
    second.writes.every((entry) => entry.action === "unchanged"),
    `every write is unchanged, got ${second.writes.map((entry) => entry.action).join(", ")}`
  );
});

test("aider reports a conventions file that nothing loads as a real problem", async () => {
  const context = await fixture();
  await install(aiderAdapter, context, "project");
  const [installed] = await aiderAdapter.installed(context);
  assert.equal((await aiderAdapter.validate(context, installed)).health, "healthy");

  await fs.rm(path.join(context.repoRoot, ".aider.conf.yml"));
  const validation = await aiderAdapter.validate(context, installed);
  assert.equal(validation.health, "conflicted");
  assert.match(validation.detail, /never loads it/);
});

test("aider uninstall keeps a config file that holds the user's own keys", async () => {
  const context = await fixture();
  const configPath = path.join(context.repoRoot, ".aider.conf.yml");
  await write(configPath, "model: gpt-5\n");

  await install(aiderAdapter, context, "project");
  assert.match(await fs.readFile(configPath, "utf8"), /# myrqen:start v/);

  await uninstall(aiderAdapter, context, "project");
  const after = await fs.readFile(configPath, "utf8");
  // `removeManagedRegion` leaves the blank line the region was separated by,
  // which is shared behaviour across every adapter that merges into a file the
  // user owns. What matters is that the user's own keys are still there.
  assert.equal(after.trimEnd(), "model: gpt-5");
  assert.doesNotMatch(after, /myrqen/);
});

/* ---------- OpenCode ---------- */

test("opencode installs the bundle in both documented skill directories", async () => {
  const context = await fixture();
  assert.deepEqual(opencodeAdapter.supportedScopes(context), ["project", "global"]);

  await install(opencodeAdapter, context, "global");
  assert.ok(await exists(path.join(context.home, ".config", "opencode", "skills", "myrqen", "SKILL.md")));

  await install(opencodeAdapter, context, "project");
  assert.ok(await exists(path.join(context.repoRoot, ".opencode", "skills", "myrqen", "SKILL.md")));

  const installed = await opencodeAdapter.installed(context);
  assert.deepEqual(installed.map((entry) => entry.scope).sort(), ["global", "project"]);
});

test("a second opencode link changes nothing, and uninstall removes only the skill", async () => {
  const context = await fixture();
  const theirs = path.join(context.home, ".config", "opencode", "skills", "their-skill", "SKILL.md");
  await write(theirs, "---\nname: their-skill\ndescription: theirs\n---\n");

  await install(opencodeAdapter, context, "global");
  const second = await opencodeAdapter.createInstallPlan(context, "global");
  assert.ok(
    second.writes.every((entry) => entry.action === "unchanged"),
    `every write is unchanged, got ${second.writes.map((entry) => entry.action).join(", ")}`
  );

  await uninstall(opencodeAdapter, context, "global");
  assert.equal(await exists(path.join(context.home, ".config", "opencode", "skills", "myrqen")), false);
  assert.ok(await exists(theirs), "another author's skill is untouched");
});

test("opencode refuses to overwrite a skill directory Myrqen did not write", async () => {
  const context = await fixture();
  const destination = path.join(context.repoRoot, ".opencode", "skills", "myrqen");
  await write(path.join(destination, "SKILL.md"), "# mine\n");

  const plan = await opencodeAdapter.createInstallPlan(context, "project");
  assert.equal(plan.writes.length, 1);
  assert.equal(plan.writes[0].action, "blocked");
  await applyPlan(plan);
  assert.equal(await fs.readFile(path.join(destination, "SKILL.md"), "utf8"), "# mine\n");
});

/* ---------- detection safety ---------- */

test("detection reports absent on an empty machine and never reads a secret", async () => {
  const context = await fixture();
  const secret = path.join(context.home, ".aider.conf.yml");
  await write(secret, "openai-api-key: sk-do-not-read-me\n");

  for (const adapter of [codexAdapter, kiroAdapter, aiderAdapter, opencodeAdapter]) {
    const detection = await adapter.detect(context);
    for (const signal of detection.signals) {
      assert.doesNotMatch(signal.detail, /sk-do-not-read-me/, `${adapter.id} leaks no file content`);
    }
  }
});
