#!/usr/bin/env node
/**
 * Why did a benchmark case pass or fail?
 *
 * The scorer answers "how many", which is the number that goes in a release
 * note. This answers "what happened to this one file", which is the only thing
 * that makes a miss fixable: whether an entry point was recognised, which
 * candidates the engine produced and where, and how each of them compares to the
 * ground truth's class, line window, and route.
 *
 *   node benchmark/explain.mjs --corpus benchmark/holdout
 *   node benchmark/explain.mjs --corpus benchmark/holdout --case holdout-nestjs-profile-patch
 *   node benchmark/explain.mjs --kind safe --verbose
 */
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
/**
 * The engine under test.
 *
 * Defaults to the workspace build. `--engine <dir>` points at a private build
 * instead, so two people can measure two different versions of the scanner at
 * the same time without one overwriting the other's `dist`.
 */
const ENGINE = (() => {
  const index = process.argv.indexOf("--engine");
  const value = index === -1 ? null : process.argv[index + 1];
  return value && !value.startsWith("--") ? value : "../packages/scan/dist/index.js";
})();
const { scan } = await import(ENGINE.startsWith(".") ? ENGINE : `file://${ENGINE}`);

const ROOT = path.resolve(import.meta.dirname, "..");
const argv = process.argv.slice(2);
function flag(name, fallback = null) {
  const index = argv.indexOf(`--${name}`);
  if (index === -1) return fallback;
  const value = argv[index + 1];
  return value && !value.startsWith("--") ? value : true;
}

const CORPUS = path.resolve(ROOT, flag("corpus", "benchmark/corpus"));
const only = flag("case");
const kindFilter = flag("kind");
const verbose = flag("verbose") === true;

const manifest = JSON.parse(await fs.readFile(path.join(CORPUS, "manifest.json"), "utf8"));

function defaultScanPath(entry) {
  if (entry.family.startsWith("nextjs")) return entry.file.split("/").slice(1).join("/");
  return path.join("src", path.basename(entry.file));
}

function routeMatches(reported, expected) {
  if (!expected) return true;
  if (!reported) return false;
  if (reported === expected) return true;
  const [reportedMethod, ...reportedRest] = reported.split(" ");
  const [expectedMethod, ...expectedRest] = expected.split(" ");
  const reportedPath = reportedRest.join(" ");
  const expectedPath = expectedRest.join(" ");
  if (!reportedPath || !expectedPath) return false;
  if (reportedMethod !== expectedMethod && reportedMethod !== "ANY") return false;
  if (reportedPath === "/") return true;
  return expectedPath === reportedPath || expectedPath.endsWith(`/${reportedPath.replace(/^\/+/, "")}`);
}

let missed = 0;
let hit = 0;
let noisy = 0;

for (const entry of manifest.cases) {
  if (only && entry.id !== only) continue;
  if (kindFilter && entry.kind !== kindFilter) continue;

  const source = await fs.readFile(path.join(CORPUS, entry.file), "utf8");
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-explain-"));
  let result;
  try {
    const target = path.join(root, entry.scanAs ?? defaultScanPath(entry));
    await fs.mkdir(path.dirname(target), { recursive: true });
    await fs.writeFile(target, source, "utf8");
    await fs.writeFile(
      path.join(root, "package.json"),
      `${JSON.stringify(entry.packageJson ?? { name: "case", version: "1.0.0" }, null, 2)}\n`,
      "utf8"
    );
    for (const [relative, contents] of Object.entries(entry.extraFiles ?? {})) {
      const extra = path.join(root, relative);
      await fs.mkdir(path.dirname(extra), { recursive: true });
      await fs.writeFile(extra, contents, "utf8");
    }
    result = await scan({ repoRoot: root });
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }

  const candidates = result.candidates;

  if (entry.kind === "safe") {
    if (candidates.length === 0) continue;
    noisy += 1;
    process.stdout.write(`\nFALSE POSITIVE  ${entry.id}  (${entry.file})\n`);
    for (const candidate of candidates) {
      process.stdout.write(`   ${candidate.ruleId} line ${candidate.location.line} route ${candidate.route ?? "—"}\n`);
      if (verbose) process.stdout.write(`      ${candidate.reasoning}\n`);
    }
    continue;
  }

  const [from, to] = entry.lineRange ?? [entry.line, entry.line];
  const satisfying = candidates.find(
    (candidate) =>
      candidate.category === entry.category &&
      routeMatches(candidate.route, entry.route) &&
      candidate.location.line >= from &&
      candidate.location.line <= to
  );
  if (satisfying) {
    hit += 1;
    if (!verbose) continue;
    process.stdout.write(`\nHIT   ${entry.id}  ${satisfying.ruleId}@${satisfying.location.line}\n`);
    continue;
  }

  missed += 1;
  const sameClass = candidates.filter((candidate) => candidate.category === entry.category);
  const reason =
    candidates.length === 0
      ? "no candidate at all"
      : sameClass.length === 0
        ? `nothing of class ${entry.category}`
        : sameClass.every((candidate) => candidate.location.line < from || candidate.location.line > to)
          ? "right class, wrong line"
          : "right class and line, route did not match";

  process.stdout.write(`\nMISS  ${entry.id}  ${entry.category}  expect line ${from}-${to} route ${entry.route ?? "—"}\n`);
  process.stdout.write(`   because: ${reason}\n`);
  process.stdout.write(
    `   candidates: ${
      candidates.map((candidate) => `${candidate.ruleId}@${candidate.location.line}[${candidate.route ?? "—"}]`).join(", ") || "(none)"
    }\n`
  );
  if (verbose) {
    for (const note of result.coverage.notAssessed.filter((line) => line.includes("route"))) {
      process.stdout.write(`   coverage: ${note}\n`);
    }
  }
}

process.stdout.write(`\n${hit} hit, ${missed} missed, ${noisy} safe case(s) with findings\n`);
