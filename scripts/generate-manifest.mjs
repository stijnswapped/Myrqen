#!/usr/bin/env node
/**
 * Regenerates BUILD-KIT-MANIFEST.md and FILE-SHA256SUMS.txt for the tracked tree,
 * so a recipient can confirm they received the repository intact.
 */
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

const ROOT = path.resolve(import.meta.dirname, "..");
const IGNORED = new Set([
  "node_modules",
  ".git",
  ".next",
  "dist",
  "dist-tsc",
  "build",
  ".turbo",
  "coverage",
  ".myrqen",
  ".data",
  "release",
  ".DS_Store"
]);
// Generated at build time by apps/cli/build.mjs from packages/skill/myrqen.
const IGNORED_PATHS = ["apps/cli/skill/"];

const IGNORED_FILES = new Set([
  ".env",
  "FILE-SHA256SUMS.txt",
  "BUILD-KIT-MANIFEST.md",
  "pnpm-lock.yaml",
  "benchmark/last-run.json"
]);

const files = [];

async function walk(directory, relative = "") {
  for (const entry of (await fs.readdir(directory, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
    if (IGNORED.has(entry.name)) continue;
    const rel = relative ? `${relative}/${entry.name}` : entry.name;
    if (IGNORED_FILES.has(rel) || IGNORED_PATHS.some((prefix) => rel.startsWith(prefix))) continue;
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) await walk(full, rel);
    else if (entry.isFile()) files.push(rel);
  }
}

await walk(ROOT);

const sums = [];
for (const file of files) {
  const body = await fs.readFile(path.join(ROOT, file));
  sums.push(`${crypto.createHash("sha256").update(body).digest("hex")}  ${file}`);
}

await fs.writeFile(path.join(ROOT, "FILE-SHA256SUMS.txt"), `${sums.join("\n")}\n`, "utf8");

const byTopLevel = new Map();
for (const file of files) {
  const top = file.includes("/") ? file.slice(0, file.indexOf("/")) : ".";
  byTopLevel.set(top, (byTopLevel.get(top) ?? 0) + 1);
}

const manifest = [
  "# Repository manifest",
  "",
  "Working codename: Myrqen.",
  "",
  `Tracked files: ${files.length}. Regenerate with \`node scripts/generate-manifest.mjs\`.`,
  "",
  "Excluded from both this manifest and the checksum file: build output, dependencies,",
  "local scan state, `.env`, the lockfile, and generated release artifacts.",
  "",
  "## Files by area",
  "",
  "| area | files |",
  "| --- | --- |",
  ...[...byTopLevel.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([top, count]) => `| \`${top}\` | ${count} |`),
  "",
  "## Verifying",
  "",
  "```bash",
  "shasum -a 256 -c FILE-SHA256SUMS.txt   # macOS",
  "sha256sum -c FILE-SHA256SUMS.txt       # Linux",
  "node scripts/verify-kit.mjs            # structural check",
  "```",
  "",
  "## Included files",
  "",
  ...files.map((file) => `- \`${file}\``),
  ""
].join("\n");

await fs.writeFile(path.join(ROOT, "BUILD-KIT-MANIFEST.md"), manifest, "utf8");
process.stdout.write(`manifest and checksums regenerated for ${files.length} files\n`);
