/** The portable bundle is the behavioural source of truth; keep it honest. */
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";

const BUNDLE = path.resolve(import.meta.dirname, "..", "myrqen");

async function read(file) {
  return fs.readFile(path.join(BUNDLE, file), "utf8");
}

test("SKILL.md declares the frontmatter the host agents read", async () => {
  const body = await read("SKILL.md");
  const [, frontmatter] = body.split("---\n", 3);
  assert.match(frontmatter, /^name: myrqen$/m);
  assert.match(frontmatter, /^description: .{40,}/m, "the description tells the model when to use the skill");
  assert.match(body, /\$ARGUMENTS/, "effort arrives through the documented placeholder");
});

test("the skill states the non-negotiable rules", async () => {
  const body = await read("SKILL.md");
  for (const rule of [
    /Never ask the user for an LLM or model provider API key/i,
    /exact/i,
    /Nothing destructive/i,
    /untrusted/i,
    /Secrets stay local/i,
    /No source changes during assessment/i,
    /Honesty about coverage/i
  ]) {
    assert.match(body, rule);
  }
});

test("the skill tells the agent to ask the sync question exactly once", async () => {
  const body = await read("SKILL.md");
  assert.match(body, /session sync-decision yes/);
  assert.match(body, /If the CLI reports `quota_blocked`, do not ask/);
});

test("the skill stays within the recommended size and points at its references", async () => {
  const body = await read("SKILL.md");
  assert.ok(body.split("\n").length < 500, "SKILL.md should stay under 500 lines");
  for (const reference of ["METHODOLOGY.md", "SAFETY.md", "FINDINGS.md", "CLI.md"]) {
    assert.match(body, new RegExp(`references/${reference}`));
    const content = await read(path.join("references", reference));
    assert.ok(content.length > 500, `${reference} should carry real content`);
  }
});

test("the safety reference treats private network ranges as external", async () => {
  const safety = await read("references/SAFETY.md");
  assert.match(safety, /192\.168/);
  assert.match(safety, /are \*not\*\s+local/, "private ranges are explicitly not local");
  assert.match(safety, /Higher effort means more depth, never fewer rules/);
});

test("the finding reference matches the submission schema fields", async () => {
  const findings = await read("references/FINDINGS.md");
  const schema = JSON.parse(
    await fs.readFile(path.resolve(BUNDLE, "..", "..", "..", "schemas", "finding-submission.schema.json"), "utf8")
  );
  for (const field of schema.required) {
    assert.match(findings, new RegExp(`\`${field}\``), `${field} should be documented`);
  }
  assert.match(findings, /Do not send an `id`/);
});
