import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import { CREDENTIAL_SHAPES } from "../dist/rules/credentials.js";

/**
 * The Python engine mirrors the JavaScript engine's credential shapes rather than
 * importing them (the dependency runs the other way). This keeps the two lists
 * from drifting apart: a shape added on one side only fails here.
 */
test("credential shapes match the JavaScript engine's list", async () => {
  const source = await fs.readFile(path.resolve(import.meta.dirname, "../../scan/src/rules/credentials.ts"), "utf8");
  const start = source.indexOf("const CREDENTIAL_SHAPES");
  assert.ok(start >= 0, "the JavaScript engine's CREDENTIAL_SHAPES table moved; update this test");
  const end = source.indexOf("\n];", start);
  const javascriptIds = [...source.slice(start, end).matchAll(/\bid:\s*"([a-z0-9_]+)"/g)].map((match) => match[1]).sort();
  const pythonIds = CREDENTIAL_SHAPES.map((shape) => shape.id).sort();
  assert.deepEqual(pythonIds, javascriptIds);
});
