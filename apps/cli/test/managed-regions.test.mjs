/**
 * Regressions for the ways this installer was found to destroy user content.
 *
 * Every case here was a reproducible defect at some point, found by reviewers
 * whose only brief was to break the tool. They are written against the real
 * behaviour a user would see — the bytes on disk afterwards — rather than
 * against the internals, because each of them passed every internal test that
 * existed at the time.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { existsSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

const ROOT = path.resolve(import.meta.dirname, "..", "..", "..");
const DIST = path.join(ROOT, "apps", "cli", "dist-tsc");

const managed = await import(pathToFileURL(path.join(DIST, "integrations", "managed.js")).href);
const { applyPlan } = await import(pathToFileURL(path.join(DIST, "integrations", "apply.js")).href);

async function scratch() {
  return fs.mkdtemp(path.join(os.tmpdir(), "myrqen-regions-"));
}

/* ---------- one name for the skill marker ---------- */

test("the skill marker filename is written down in exactly one place", async () => {
  // Two adapters install skill bundles — Claude Code's, and the planner the
  // Codex, Kiro, and OpenCode adapters share — and the marker is the only thing
  // that tells either of them that a directory is Myrqen's own work rather than
  // a stranger's skill of the same name. A second spelling of the name is not a
  // typo that fails loudly: one writer would refuse to update what the other
  // installed, and `status` would report a skill that is plainly on disk as
  // missing. This test is what makes that impossible to reintroduce quietly.
  const sources = [];
  const walk = async (directory) => {
    for (const entry of await fs.readdir(directory, { withFileTypes: true })) {
      const full = path.join(directory, entry.name);
      if (entry.isDirectory()) await walk(full);
      else if (entry.isFile() && full.endsWith(".ts")) sources.push(full);
    }
  };
  await walk(path.join(ROOT, "apps", "cli", "src"));

  const declaring = [];
  for (const source of sources) {
    if ((await fs.readFile(source, "utf8")).includes(managed.SKILL_MARKER_FILE)) declaring.push(source);
  }

  assert.deepEqual(
    declaring.map((file) => path.relative(ROOT, file).split(path.sep).join("/")),
    ["apps/cli/src/integrations/managed.ts"],
    "every other file must import SKILL_MARKER_FILE rather than repeat the literal"
  );
  assert.equal(managed.SKILL_MARKER_FILE, ".myrqen-managed.json", "the name installs already on disk carry");
});

/* ---------- the marker must own its own line ---------- */

test("a file that merely mentions the start marker keeps its content", async () => {
  // A README, a changelog, or a support answer explaining what Myrqen writes
  // will quote the marker. Matching that mention as the start of the region made
  // the next link replace everything between the sentence and the real region.
  const documented = [
    "# Team instructions",
    "",
    "Myrqen writes a block that begins with <!-- myrqen:start v2 --> and ends with a matching close.",
    "",
    "## Deployment",
    "Never deploy on a Friday.",
    ""
  ].join("\n");

  const first = managed.mergeManagedRegion(documented, "PAYLOAD ONE", "html");
  const second = managed.mergeManagedRegion(first.contents, "PAYLOAD TWO", "html");

  assert.match(second.contents, /Never deploy on a Friday\./, "the user's own section survived");
  assert.match(second.contents, /Myrqen writes a block that begins with/, "the prose mention survived");
  assert.equal(
    (second.contents.match(/myrqen:end/g) ?? []).length,
    1,
    "exactly one managed region, not one swallowing the prose"
  );
  assert.match(second.contents, /PAYLOAD TWO/);
  assert.doesNotMatch(second.contents, /PAYLOAD ONE/);
});

/* ---------- removal touches the seam, not the document ---------- */

test("removing the region does not reformat the rest of the file", async () => {
  const original = [
    "    indented first line",
    "",
    "# Team instructions",
    "",
    "```python",
    "def a():",
    "    pass",
    "",
    "",
    "",
    "def b():",
    "    pass",
    "```",
    "",
    "End of file.",
    ""
  ].join("\n");

  const merged = managed.mergeManagedRegion(original, "PAYLOAD", "html");
  const removed = managed.removeManagedRegion(merged.contents, "html");

  assert.equal(removed.removed, true);
  assert.equal(
    removed.contents,
    original,
    "link followed by unlink returns the file byte for byte, including the blank lines inside the code fence and the indented first line"
  );
});

test("a byte-order mark survives a link and an unlink", async () => {
  const original = `﻿# Instructions\n\nBe careful.\n`;
  const merged = managed.mergeManagedRegion(original, "PAYLOAD", "html");
  const removed = managed.removeManagedRegion(merged.contents, "html");
  assert.equal(removed.contents, original);
});

test("CRLF files keep CRLF and gain no lone newline", async () => {
  const original = "# Rules\r\n\r\nUse pnpm.\r\n";
  const merged = managed.mergeManagedRegion(original, "PAYLOAD", "html");
  assert.ok(merged.contents.includes("\r\n"));
  assert.ok(!/[^\r]\n/.test(merged.contents), "no bare LF was introduced");
  const removed = managed.removeManagedRegion(merged.contents, "html");
  assert.equal(removed.contents, original);
});

/* ---------- identity of the file on disk ---------- */

test("writing through a symlink keeps the link", async (t) => {
  const base = await scratch();
  try {
    const shared = path.join(base, "shared.md");
    const link = path.join(base, "AGENTS.md");
    await fs.writeFile(shared, "# Shared\nOne source of truth.\n");
    try {
      await fs.symlink(shared, link);
    } catch (error) {
      // Windows lets only administrators and Developer Mode create symlinks.
      if (error.code === "EPERM" && process.platform === "win32") {
        t.skip("this Windows account may not create symlinks");
        return;
      }
      throw error;
    }

    await managed.writeAtomic(link, "# Shared\nOne source of truth.\nplus a region\n");

    const stat = await fs.lstat(link);
    assert.equal(stat.isSymbolicLink(), true, "AGENTS.md is still a symlink");
    assert.match(await fs.readFile(shared, "utf8"), /plus a region/, "the write reached the shared file");
  } finally {
    await fs.rm(base, { recursive: true, force: true });
  }
});

test("a file that is not valid UTF-8 is refused rather than rewritten", async () => {
  const base = await scratch();
  try {
    const target = path.join(base, "AGENTS.md");
    // Latin-1, as plenty of older European repositories still are.
    await fs.writeFile(target, Buffer.from([0x23, 0x20, 0x52, 0xe8, 0x67, 0x6c, 0x65, 0x73, 0x0a]));
    assert.equal(await managed.readsBackUnchanged(target), false);

    const utf8 = path.join(base, "OK.md");
    await fs.writeFile(utf8, "# Règles\n", "utf8");
    assert.equal(await managed.readsBackUnchanged(utf8), true);

    // A path that does not exist yet cannot be corrupted by being created.
    assert.equal(await managed.readsBackUnchanged(path.join(base, "absent.md")), true);
  } finally {
    await fs.rm(base, { recursive: true, force: true });
  }
});

test("writability is judged against the nearest directory that exists", async () => {
  const base = await scratch();
  try {
    // A plan routinely creates several levels at once. Asking whether a
    // directory that has not been made yet is writable answered no for every
    // file in a skill bundle, and blocked the whole install.
    const deep = path.join(base, "a", "b", "c", "file.md");
    assert.equal(await managed.isWritable(deep), true);

    const existing = path.join(base, "present.md");
    await fs.writeFile(existing, "x");
    await fs.chmod(existing, 0o444);
    assert.equal(await managed.isWritable(existing), false, "a read-only file is reported as such");
    await fs.chmod(existing, 0o644);
  } finally {
    await fs.rm(base, { recursive: true, force: true });
  }
});

/* ---------- what the applier removes ---------- */

test("uninstall removes the directories it emptied and nothing above them", async () => {
  const base = await scratch();
  try {
    // A directory the user made, holding a directory Myrqen made.
    const userOwned = path.join(base, ".github");
    const myrqenOwned = path.join(userOwned, "instructions");
    await fs.mkdir(myrqenOwned, { recursive: true });
    const file = path.join(myrqenOwned, "myrqen.instructions.md");
    await fs.writeFile(file, "payload");

    const applied = await applyPlan({
      adapterId: "test",
      displayName: "Test",
      scope: "project",
      writes: [
        {
          path: file,
          displayPath: ".github/instructions/myrqen.instructions.md",
          action: "remove",
          preservesExistingContent: false
        }
      ],
      notes: []
    });

    assert.equal(applied.ok, true);
    assert.equal(existsSync(file), false, "Myrqen's file is gone");
    assert.equal(existsSync(myrqenOwned), false, "the directory it emptied is gone");
    assert.equal(existsSync(userOwned), true, "the directory above it is the user's and stays");
  } finally {
    await fs.rm(base, { recursive: true, force: true });
  }
});

test("a sibling file keeps its directory alive", async () => {
  const base = await scratch();
  try {
    const rules = path.join(base, ".cursor", "rules");
    await fs.mkdir(rules, { recursive: true });
    const ours = path.join(rules, "myrqen.mdc");
    const theirs = path.join(rules, "team.mdc");
    await fs.writeFile(ours, "payload");
    await fs.writeFile(theirs, "the user's own rule");

    await applyPlan({
      adapterId: "test",
      displayName: "Test",
      scope: "project",
      writes: [
        { path: ours, displayPath: ".cursor/rules/myrqen.mdc", action: "remove", preservesExistingContent: false }
      ],
      notes: []
    });

    assert.equal(existsSync(ours), false);
    assert.equal(existsSync(rules), true, "the rules directory survives because it is not empty");
    assert.equal(await fs.readFile(theirs, "utf8"), "the user's own rule");
  } finally {
    await fs.rm(base, { recursive: true, force: true });
  }
});

/* ---------- rollback ---------- */

test("a plan that fails partway restores every file it had already written", async () => {
  const base = await scratch();
  try {
    const good = path.join(base, "first.md");
    await fs.writeFile(good, "original first\n");

    // The second write targets a path whose parent is a FILE, so creating the
    // directory fails and the plan aborts after the first write succeeded.
    const blocker = path.join(base, "blocker");
    await fs.writeFile(blocker, "not a directory");
    const doomed = path.join(blocker, "second.md");

    const applied = await applyPlan({
      adapterId: "test",
      displayName: "Test",
      scope: "project",
      writes: [
        { path: good, displayPath: "first.md", action: "update", contents: "rewritten\n", preservesExistingContent: true },
        { path: doomed, displayPath: "blocker/second.md", action: "create", contents: "x", preservesExistingContent: false }
      ],
      notes: []
    });

    assert.equal(applied.ok, false, "the plan reports failure");
    assert.equal(
      await fs.readFile(good, "utf8"),
      "original first\n",
      "the write that had already succeeded was rolled back"
    );
  } finally {
    await fs.rm(base, { recursive: true, force: true });
  }
});
