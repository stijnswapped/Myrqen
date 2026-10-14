/**
 * Cline, Roo Code, and Continue: a dedicated file in someone else's rules
 * directory, never a rewrite of what is already there.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

const ROOT = path.resolve(import.meta.dirname, "..", "..", "..");
const DIST = path.join(ROOT, "apps", "cli", "dist-tsc", "integrations");

const { clineAdapter, rooAdapter, continueAdapter } = await import(pathToFileURL(path.join(DIST, "adapters", "vscode-rules.js")).href);
const { applyPlan } = await import(pathToFileURL(path.join(DIST, "apply.js")).href);

const ADAPTERS = [
  { adapter: clineAdapter, id: "cline", project: ".clinerules/myrqen.md" },
  { adapter: rooAdapter, id: "roo-code", project: ".roo/rules/myrqen.md" },
  { adapter: continueAdapter, id: "continue", project: ".continue/rules/myrqen.md" }
];

/**
 * A machine of our own. repoRoot and home are siblings so that a global target
 * can never be mistaken for a project one, and neither is anywhere near the
 * developer's real configuration.
 */
async function fixture() {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-vscode-rules-"));
  const repoRoot = path.join(base, "repo");
  const home = path.join(base, "home");
  await fs.mkdir(repoRoot, { recursive: true });
  await fs.mkdir(home, { recursive: true });
  return { base, repoRoot, home, platform: process.platform, env: {}, skillSource: "" };
}

async function read(target) {
  return fs.readFile(target, "utf8");
}

async function missing(target) {
  return fs
    .access(target)
    .then(() => false)
    .catch(() => true);
}

async function install(adapter, context, scope = "project") {
  const plan = await adapter.createInstallPlan(context, scope);
  const applied = await applyPlan(plan);
  assert.ok(applied.ok, `applying the ${adapter.id} plan failed`);
  return plan;
}

test("an empty project gets one dedicated file per agent and nothing else", async () => {
  const context = await fixture();

  for (const { adapter, id, project } of ADAPTERS) {
    const plan = await adapter.createInstallPlan(context, "project");
    assert.equal(plan.adapterId, id);
    assert.equal(plan.writes.length, 1, `${id} writes exactly one file`);

    const [write] = plan.writes;
    assert.equal(write.action, "create");
    assert.equal(write.displayPath, project);
    assert.equal(write.preservesExistingContent, false);
    assert.match(write.contents, /myrqen:start v/, "the file carries a managed marker");
    assert.match(write.contents, /myrqen:end/);
    assert.ok(write.contents.length < 4000, `${id} gets the pointer, not the whole method`);

    // Planning is pure: nothing exists until the applier runs.
    assert.ok(await missing(write.path), `${id} wrote a file while planning`);
  }
});

test("Continue's frontmatter is the first bytes of the file and the marker sits below it", async () => {
  const context = await fixture();
  const plan = await continueAdapter.createInstallPlan(context, "project");
  const body = plan.writes[0].contents;

  assert.ok(body.startsWith("---\n"), "YAML frontmatter must open the file");
  const closing = body.indexOf("\n---\n", 3);
  assert.ok(closing > 0, "the frontmatter block is closed");
  assert.ok(!body.slice(0, closing).includes("<!--"), "no HTML comment inside the YAML header");
  assert.ok(body.indexOf("<!-- myrqen:start") > closing, "the managed region follows the header");
  assert.match(body, /alwaysApply: true/);
});

test("each agent's documented global location is used, and only documented scopes are offered", async () => {
  const context = await fixture();

  for (const { adapter } of ADAPTERS) {
    assert.deepEqual(adapter.supportedScopes(context), ["project", "global"]);
  }

  const cline = await clineAdapter.createInstallPlan(context, "global");
  assert.equal(cline.writes[0].path, path.join(context.home, "Documents", "Cline", "Rules", "myrqen.md"));

  const roo = await rooAdapter.createInstallPlan(context, "global");
  assert.equal(roo.writes[0].path, path.join(context.home, ".roo", "rules", "myrqen.md"));

  const kontinue = await continueAdapter.createInstallPlan(context, "global");
  assert.equal(kontinue.writes[0].path, path.join(context.home, ".continue", "rules", "myrqen.md"));
});

test("a rules file the user already wrote is preserved byte for byte", async () => {
  const context = await fixture();
  const own = "# House rules\n\nAlways run the linter before committing.\n";

  for (const { adapter, id, project } of ADAPTERS) {
    const target = path.join(context.repoRoot, ...project.split("/"));
    await fs.mkdir(path.dirname(target), { recursive: true });
    await fs.writeFile(target, own);

    const plan = await adapter.createInstallPlan(context, "project");
    const [write] = plan.writes;
    assert.equal(write.action, "merge", `${id} merges into a file it did not write`);
    assert.equal(write.preservesExistingContent, true);
    assert.ok(write.contents.startsWith(own.trimEnd()), `${id} kept the user's text at the top`);

    await applyPlan(plan);
    const merged = await read(target);
    assert.ok(merged.includes("Always run the linter before committing."));
    assert.match(merged, /myrqen:start v/);
  }
});

test("a legacy .clinerules file is added to, never converted into a directory", async () => {
  const context = await fixture();
  const legacy = path.join(context.repoRoot, ".clinerules");
  const own = "Use tabs. Never reformat generated code.\n";
  await fs.writeFile(legacy, own);

  const plan = await clineAdapter.createInstallPlan(context, "project");
  const [write] = plan.writes;
  assert.equal(write.path, legacy);
  assert.equal(write.action, "merge");
  assert.equal(write.preservesExistingContent, true);
  assert.ok(
    plan.notes.some((note) => note.includes(".clinerules is a single file")),
    "the plan says why the payload went into the existing file"
  );

  await applyPlan(plan);
  const merged = await read(legacy);
  assert.ok(merged.startsWith(own.trimEnd()), "the user's file still opens with their own text");
  assert.ok((await fs.stat(legacy)).isFile(), ".clinerules is still a file");
  assert.ok(await missing(path.join(context.repoRoot, ".clinerules", "myrqen.md")));

  // And it comes back out again, leaving the file the user wrote.
  const uninstall = await clineAdapter.createUninstallPlan(context, "project");
  assert.equal(uninstall.writes[0].action, "remove");
  assert.equal(uninstall.writes[0].preservesExistingContent, true);
  await applyPlan(uninstall);
  const left = await read(legacy);
  // Trailing whitespace is normalised by the shared region remover; the user's
  // own line is what must survive, and no marker may be left behind.
  assert.equal(left.trimEnd(), own.trimEnd());
  assert.ok(!left.includes("myrqen:"));
});

test("a second run on an unchanged install changes nothing", async () => {
  const context = await fixture();

  for (const { adapter, id } of ADAPTERS) {
    await install(adapter, context);

    const second = await adapter.createInstallPlan(context, "project");
    assert.equal(second.writes[0].action, "unchanged", `${id} is not idempotent`);
    assert.equal(second.writes[0].contents, undefined, "an unchanged write carries no content");

    const applied = await applyPlan(second);
    assert.ok(applied.writes.every((entry) => entry.outcome === "unchanged"));
  }
});

test("an install is reconstructed from the marker on disk and reports healthy", async () => {
  const context = await fixture();

  for (const { adapter, id, project } of ADAPTERS) {
    await install(adapter, context);

    const installed = await adapter.installed(context);
    assert.equal(installed.length, 1, `${id} reports exactly the project install`);
    const [entry] = installed;
    assert.equal(entry.adapterId, id);
    assert.equal(entry.scope, "project");
    assert.equal(entry.displayPath, project);
    assert.equal(entry.sharedFile, false, "a dedicated file is not shared");

    const validation = await adapter.validate(context, entry);
    assert.equal(validation.health, "healthy", validation.detail);
  }
});

test("a stale payload and a duplicated region are both reported, not silently rewritten", async () => {
  const context = await fixture();
  await install(rooAdapter, context);
  const target = path.join(context.repoRoot, ".roo", "rules", "myrqen.md");

  const current = await read(target);
  await fs.writeFile(target, current.replace(/myrqen:start v[^ ]+ /, "myrqen:start v1 "));
  const [stale] = await rooAdapter.installed(context);
  assert.equal(stale.payloadVersion, "1");
  assert.equal((await rooAdapter.validate(context, stale)).health, "stale");

  await fs.writeFile(target, `${current}\n${current}`);
  const [duplicated] = await rooAdapter.installed(context);
  assert.equal((await rooAdapter.validate(context, duplicated)).health, "conflicted");

  const blocked = await rooAdapter.createInstallPlan(context, "project");
  assert.equal(blocked.writes[0].action, "blocked");
  assert.equal(blocked.writes[0].contents, undefined);
  assert.ok(blocked.writes[0].reason.length > 0);
});

test("uninstalling removes only Myrqen's file and leaves the rules directory alone", async () => {
  const context = await fixture();

  for (const { adapter, id, project } of ADAPTERS) {
    const directory = path.dirname(path.join(context.repoRoot, ...project.split("/")));
    await fs.mkdir(directory, { recursive: true });
    const neighbour = path.join(directory, "team-conventions.md");
    await fs.writeFile(neighbour, "# Team conventions\n");

    await install(adapter, context);

    const plan = await adapter.createUninstallPlan(context, "project");
    assert.equal(plan.writes.length, 1, `${id} touches one file when uninstalling`);
    assert.equal(plan.writes[0].action, "remove");
    assert.equal(plan.writes[0].contents, undefined, "a file that is only Myrqen's is deleted, not blanked");

    const applied = await applyPlan(plan);
    assert.ok(applied.ok);
    assert.ok(await missing(plan.writes[0].path), `${id} left its file behind`);
    assert.equal(await read(neighbour), "# Team conventions\n", `${id} disturbed a neighbouring rule file`);
    assert.ok((await fs.stat(directory)).isDirectory(), `${id} removed the rules directory`);
    assert.deepEqual(await adapter.installed(context), []);

    const again = await adapter.createUninstallPlan(context, "project");
    assert.equal(again.writes[0].action, "unchanged", `${id} is not idempotent when uninstalling`);
  }
});

test("detection is honest on a machine with none of these agents installed", async () => {
  const context = await fixture();
  const emptyPath = path.join(context.base, "no-executables");
  await fs.mkdir(emptyPath, { recursive: true });

  const originalPath = process.env.PATH;
  process.env.PATH = emptyPath;
  try {
    for (const { adapter, id } of ADAPTERS) {
      const detection = await adapter.detect(context);
      assert.equal(detection.detected, false, `${id} claimed to be installed on an empty machine`);
      assert.equal(detection.confidence, "absent");
      assert.deepEqual(detection.signals, []);
    }

    // A repository configured by a colleague proves nothing about this machine.
    await fs.writeFile(path.join(context.repoRoot, ".roorules"), "# their rules\n");
    const projectOnly = await rooAdapter.detect(context);
    assert.equal(projectOnly.confidence, "project_only");

    // The agent's own configuration directory is one credible signal, no more.
    await fs.mkdir(path.join(context.home, ".continue"), { recursive: true });
    const probable = await continueAdapter.detect(context);
    assert.equal(probable.confidence, "probable");
    assert.ok(probable.signals.some((signal) => signal.kind === "config_directory"));
  } finally {
    process.env.PATH = originalPath;
  }
});
