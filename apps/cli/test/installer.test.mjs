/**
 * The portable skill bundle ships with the built CLI and is where the CLI says.
 *
 * This file used to cover a second, imperative installer as well —
 * `agentTargets()`, `detectAgents()`, and `installSkill()`. That installer was
 * superseded by the adapter layer in `src/integrations/`, which plans every
 * write, shows it to the user, and applies it through one applier that can roll
 * back. Both wrote `.claude/skills/myrqen`, so the second one was deleted rather
 * than kept in step; what an installed skill directory looks like is now covered
 * by `adapters-claude.test.mjs` and `misc-adapters.test.mjs`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const run = promisify(execFile);
const ROOT = path.resolve(import.meta.dirname, "..", "..", "..");
const CLI = path.join(ROOT, "apps", "cli", "dist", "myrqen.mjs");

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
