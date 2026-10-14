import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { parseFile } from "../../dist/ast/parse.js";
import { discoverRoutes } from "../../dist/ast/routes.js";

/**
 * Drive a set of rules over one inline source file, the way `scan()` would, and
 * return the candidates a reader would see (deduplicated on rule and line).
 *
 * `extra` writes sibling files — a `package.json`, say — beside the source, which
 * the rules that read project metadata need.
 */
export async function runRules(rules, source, filename = "src/handler.js", extra = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-rules-"));
  try {
    for (const [relative, contents] of Object.entries({ [filename]: source, ...extra })) {
      const target = path.join(root, relative);
      await fs.mkdir(path.dirname(target), { recursive: true });
      await fs.writeFile(target, contents, "utf8");
    }
    const parsed = await parseFile(root, path.join(root, filename));
    assert.ok(!("error" in parsed), `the fixture must parse: ${parsed.error ?? ""}`);
    const candidates = [];
    const context = { file: parsed, routes: discoverRoutes(parsed), report: (candidate) => candidates.push(candidate) };
    for (const rule of rules) rule.run(context);
    const seen = new Map();
    for (const candidate of candidates) {
      const key = `${candidate.ruleId}::${candidate.location.line}`;
      if (!seen.has(key)) seen.set(key, candidate);
    }
    return [...seen.values()];
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
}
