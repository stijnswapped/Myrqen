import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { scan } from "../dist/index.js";

/**
 * Three shapes the in-function model did not read: a loop over the caller's collection, a
 * callback over it, and an object literal holding caller data in one field. Each positive
 * has the near-miss that must stay silent.
 */
async function scanFiles(files) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-intra-"));
  for (const [relativePath, contents] of Object.entries(files)) {
    const target = path.join(root, relativePath);
    await fs.mkdir(path.dirname(target), { recursive: true });
    await fs.writeFile(target, contents, "utf8");
  }
  try {
    return await scan({ repoRoot: root });
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
}

const PKG = JSON.stringify({ name: "app", version: "1.0.0", type: "module", dependencies: { express: "^4.19.0" } });
const of = (result, category) => result.candidates.filter((candidate) => candidate.category === category);

const route = (body) => `import express from "express";
import { exec } from "node:child_process";
export const router = express.Router();
router.post("/batch", async (req, res) => {
${body}
  res.end();
});
`;

test("a loop over the caller's collection carries its elements", async () => {
  const result = await scanFiles({
    "package.json": PKG,
    "src/route.js": route("  for (const name of req.body.files) {\n    exec(`convert /in/${name} /out/${name}.pdf`);\n  }")
  });
  assert.equal(of(result, "command_injection").length, 1);
});

test("a loop over a constant list does not", async () => {
  const result = await scanFiles({
    "package.json": PKG,
    "src/route.js": route('  for (const name of ["a.png", "b.png"]) {\n    exec(`convert /in/${name} /out/${name}.pdf`);\n  }')
  });
  assert.equal(of(result, "command_injection").length, 0);
});

test("a callback over the caller's collection carries its elements", async () => {
  const result = await scanFiles({
    "package.json": PKG,
    "src/route.js": route("  req.body.files.forEach((name) => exec(`convert /in/${name} /out.pdf`));")
  });
  assert.equal(of(result, "command_injection").length, 1);
});

test("a callback over a constant list does not", async () => {
  const result = await scanFiles({
    "package.json": PKG,
    "src/route.js": route('  ["a", "b"].forEach((name) => exec(`convert /in/${name} /out.pdf`));')
  });
  assert.equal(of(result, "command_injection").length, 0);
});

test("an object literal holding caller data taints that field, and only that field", async () => {
  const tainted = await scanFiles({
    "package.json": PKG,
    "src/route.js": route('  const job = { file: req.body.file, owner: "system" };\n  exec(`convert /in/${job.file} /out.pdf`);')
  });
  assert.equal(of(tainted, "command_injection").length, 1);
  const clean = await scanFiles({
    "package.json": PKG,
    "src/route.js": route('  const job = { file: req.body.file, owner: "system" };\n  exec(`chown ${job.owner} /out.pdf`);')
  });
  assert.equal(of(clean, "command_injection").length, 0);
});
