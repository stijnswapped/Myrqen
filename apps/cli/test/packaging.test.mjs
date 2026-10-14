/**
 * Packaging regression tests: ensure the CLI is distributable as a standalone
 * npm package. These tests verify the build artifact exists, the manifest is
 * correct, and the bundled binary launches without the workspace.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readFile, stat } from "node:fs/promises";
import path from "node:path";

const CLI_DIR = path.resolve(import.meta.dirname, "..");
const DIST = path.join(CLI_DIR, "dist", "myrqen.mjs");
const MANIFEST = path.join(CLI_DIR, "package.json");

function run(args, opts = {}) {
  return new Promise((resolve, reject) => {
    execFile(process.execPath, args, opts, (error, stdout, stderr) => {
      if (error) error.stdout = stdout;
      if (error) error.stderr = stderr;
      resolve({ error, stdout: stdout.toString(), stderr: stderr.toString() });
    });
  });
}

test("dist/myrqen.mjs exists after build", async () => {
  const info = await stat(DIST);
  assert.ok(info.isFile(), "CLI entrypoint is a file");
  assert.ok(info.size > 1_000_000, `bundle is ${info.size} bytes, expected a bundled file`);
});

// Windows has no execute bit; npm generates a .cmd shim for the bin instead.
const NO_EXEC_BIT = process.platform === "win32" ? "Windows has no execute bit; npm writes a .cmd shim" : false;

test("dist/myrqen.mjs is executable", { skip: NO_EXEC_BIT }, async () => {
  const info = await stat(DIST);
  // Owner execute bit (0o100): what lets `./dist/myrqen.mjs` and npm's symlinked bin run.
  assert.ok((info.mode & 0o100) !== 0, "CLI entrypoint has owner execute permission");
});

test("dist/myrqen.mjs has a Node shebang", async () => {
  const firstLine = (await readFile(DIST, "utf8")).split("\n")[0];
  assert.equal(firstLine, "#!/usr/bin/env node", "first line is a Node shebang");
});

test("package.json declares the myrqen bin", async () => {
  const pkg = JSON.parse(await readFile(MANIFEST, "utf8"));
  // No "./" prefix. npm normalises it away on publish and warns
  // `"bin[myrqen]" script name dist/myrqen.mjs was invalid and removed`, which
  // reads as though the executable had been dropped from the package. It had not,
  // but a publisher who believes it runs `npm pkg fix` on a release candidate.
  assert.equal(pkg.bin?.myrqen, "dist/myrqen.mjs");
});

test("package.json is not private (publishable)", async () => {
  const pkg = JSON.parse(await readFile(MANIFEST, "utf8"));
  assert.equal(pkg.private, undefined, "package must not be private to publish");
});

test("package.json has a prepack script", async () => {
  const pkg = JSON.parse(await readFile(MANIFEST, "utf8"));
  assert.ok(pkg.scripts?.prepack, "prepack script is defined");
});

test("package.json has files allowlist covering the executable and the skill", async () => {
  const pkg = JSON.parse(await readFile(MANIFEST, "utf8"));
  assert.ok(Array.isArray(pkg.files), "files field is an array");
  // The allowlist names the executable itself rather than the whole `dist`
  // directory, so a stray artifact left there by a local build can never be
  // published by accident.
  assert.ok(
    pkg.files.some((entry) => entry === "dist" || entry === "dist/myrqen.mjs"),
    `files must cover dist/myrqen.mjs, got ${JSON.stringify(pkg.files)}`
  );
  assert.ok(pkg.files.includes("skill"), "files includes skill/");
  assert.ok(
    !pkg.files.some((entry) => entry.endsWith(".map")),
    "the source map is not published: it is larger than the bundle and nobody installing the CLI reads it"
  );
});

test("bundled binary launches and prints version", async () => {
  // Compared against the manifest rather than a literal: a hardcoded version
  // turns every release into a test failure, and a test that has to be edited
  // to release is a test people edit without reading.
  const pkg = JSON.parse(await readFile(MANIFEST, "utf8"));
  const result = await run([DIST, "--version"]);
  assert.equal(result.error, null, `binary failed: ${result.stderr}`);
  assert.equal(result.stdout.trim(), pkg.version, "the bundle must report the version it is published as");
});

test("bundled binary prints help with --help", async () => {
  const result = await run([DIST, "--help"]);
  assert.equal(result.error, null, `binary failed: ${result.stderr}`);
  assert.ok(result.stdout.includes("myrqen"), "help output mentions the tool name");
  assert.ok(result.stdout.includes("link"), "help output lists the link command");
});
