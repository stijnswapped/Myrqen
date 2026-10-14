#!/usr/bin/env node
/**
 * Two diagnostics the release scorer cannot give, because both need to relax the
 * scorer's own pass/fail predicate rather than apply it.
 *
 * **The waterfall.** `score-corpus.mjs` prints one number per corpus. That number
 * is the conjunction of five independent requirements — the file yields anything,
 * of the right class, at the right line, at the right route, in the right severity
 * band — and knowing which one failed is the whole difference between "write a
 * rule", "follow the flow further", and "fix route attribution". Each row below is
 * a strictly weaker requirement than the row under it, so each drop is the cost of
 * exactly one mechanism.
 *
 * **The mutation delta.** See `benchmark/mutate.mjs`. Scored at the *class-in-range*
 * row rather than the bottom row, because a renamed tRPC router legitimately
 * changes its own route and that is the mutant's doing, not the engine's.
 *
 * Neither gates anything. Both are for deciding what to build.
 *
 *   node benchmark/diagnose.mjs --corpus benchmark/holdout-3
 *   node benchmark/diagnose.mjs --corpus benchmark/corpus --mutate
 */
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { mutateRename } from "./mutate.mjs";

const ROOT = path.resolve(import.meta.dirname, "..");
const argv = process.argv.slice(2);
function flag(name, fallback) {
  const index = argv.indexOf(`--${name}`);
  if (index === -1) return fallback;
  const value = argv[index + 1];
  return value && !value.startsWith("--") ? value : true;
}
const ENGINE = typeof flag("engine", null) === "string" ? flag("engine", null) : path.join(ROOT, "packages/scan/dist/index.js");
const { scan } = await import(ENGINE.startsWith(".") ? ENGINE : `file://${ENGINE}`);

const CORPUS = path.resolve(ROOT, typeof flag("corpus", null) === "string" ? flag("corpus", null) : "benchmark/corpus");
const MUTATE = flag("mutate", false) === true;
const manifest = JSON.parse(await fs.readFile(path.join(CORPUS, "manifest.json"), "utf8"));

/** Kept in step with `score-corpus.mjs`; see UNSUPPORTED_LANGUAGES there. */
const UNSUPPORTED = new Set(["python", "ruby", "go", "php", "java"]);

function routeMatches(reported, expected) {
  if (!expected) return true;
  if (!reported) return false;
  if (reported === expected) return true;
  const [reportedMethod, ...reportedRest] = reported.split(" ");
  const [expectedMethod, ...expectedRest] = expected.split(" ");
  const reportedPath = reportedRest.join(" ");
  const expectedPath = expectedRest.join(" ");
  if (reportedPath.length === 0 || expectedPath.length === 0) return false;
  if (reportedMethod !== expectedMethod && reportedMethod !== "ANY") return false;
  if (reportedPath === "/") return true;
  return expectedPath === reportedPath || expectedPath.endsWith(`/${reportedPath.replace(/^\/+/, "")}`);
}

function scanPath(entry) {
  if (entry.scanAs) return entry.scanAs;
  if (entry.family.startsWith("nextjs")) return entry.file.split("/").slice(1).join("/");
  return path.join("src", path.basename(entry.file));
}

async function scanCase(entry) {
  let source = await fs.readFile(path.join(CORPUS, entry.file), "utf8");
  const relative = scanPath(entry);
  let mutated = false;
  if (MUTATE) {
    const result = mutateRename(source, relative);
    // A mutant that moved a line cannot be compared against a line range.
    if (result.source.split("\n").length === source.split("\n").length) {
      mutated = result.source !== source;
      source = result.source;
    }
  }
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-diagnose-"));
  try {
    const target = path.join(root, relative);
    await fs.mkdir(path.dirname(target), { recursive: true });
    await fs.writeFile(target, source, "utf8");
    await fs.writeFile(
      path.join(root, "package.json"),
      `${JSON.stringify(entry.packageJson ?? { name: "case", version: "1.0.0", type: "module" }, null, 2)}\n`,
      "utf8"
    );
    for (const [relativeExtra, contents] of Object.entries(entry.extraFiles ?? {})) {
      const extra = path.join(root, relativeExtra);
      await fs.mkdir(path.dirname(extra), { recursive: true });
      await fs.writeFile(extra, contents, "utf8");
    }
    const { candidates } = await scan({ repoRoot: root });
    return { candidates, mutated };
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
}

const stages = { any: 0, rightClass: 0, inRange: 0, routed: 0, banded: 0 };
let vulnerable = 0;
let mutatedFiles = 0;
const noRightClass = [];
const attribution = [];

for (const entry of manifest.cases) {
  if (entry.kind !== "vulnerable" || UNSUPPORTED.has(entry.language)) continue;
  vulnerable += 1;
  const { candidates, mutated } = await scanCase(entry);
  if (mutated) mutatedFiles += 1;
  const [from, to] = entry.lineRange ?? [entry.line, entry.line];
  const sameClass = candidates.filter((candidate) => candidate.category === entry.category);
  const inRange = sameClass.filter((candidate) => candidate.location.line >= from && candidate.location.line <= to);
  const routed = inRange.filter((candidate) => routeMatches(candidate.route, entry.route));
  const banded = routed.filter((candidate) => (entry.severityBand ?? []).includes(candidate.severity));

  if (candidates.length > 0) stages.any += 1;
  if (sameClass.length > 0) stages.rightClass += 1;
  if (inRange.length > 0) stages.inRange += 1;
  if (routed.length > 0) stages.routed += 1;
  if (banded.length > 0) stages.banded += 1;

  if (sameClass.length === 0) {
    noRightClass.push({ entry, alsoSaw: [...new Set(candidates.map((candidate) => candidate.category))] });
  } else if (routed.length === 0) {
    attribution.push({ entry, lines: sameClass.map((candidate) => candidate.location.line), routes: sameClass.map((candidate) => candidate.route ?? null) });
  }
}

const label = path.basename(CORPUS);
const ratio = (count) => `${(count / vulnerable).toFixed(3)} (${count}/${vulnerable})`;

process.stdout.write(`\n${label}${MUTATE ? " — MUT-RENAME" : ""}: ${vulnerable} vulnerable case(s)\n\n`);
process.stdout.write(`  1. the file yields any candidate        ${ratio(stages.any)}\n`);
process.stdout.write(`  2. ...of the expected class             ${ratio(stages.rightClass)}\n`);
process.stdout.write(`  3. ...inside the expected line range    ${ratio(stages.inRange)}   <- compare mutants here\n`);
process.stdout.write(`  4. ...and the route matches             ${ratio(stages.routed)}   <- the scored recall\n`);
process.stdout.write(`  5. ...and the severity is in band       ${ratio(stages.banded)}\n`);
if (MUTATE) process.stdout.write(`\n  ${mutatedFiles} file(s) mutated\n`);

if (noRightClass.length > 0) {
  process.stdout.write(`\nnothing of the expected class — rules and data flow, ${noRightClass.length} case(s):\n`);
  for (const { entry, alsoSaw } of noRightClass) {
    const saw = alsoSaw.length > 0 ? `saw ${alsoSaw.join(", ")}` : "the file yielded nothing at all";
    process.stdout.write(`  ${entry.category.padEnd(38)} ${entry.id}  (${saw})\n`);
  }
}

if (attribution.length > 0) {
  process.stdout.write(`\nright class, not scored — attribution, ${attribution.length} case(s):\n`);
  for (const { entry, lines, routes } of attribution) {
    const [from, to] = entry.lineRange ?? [entry.line, entry.line];
    process.stdout.write(
      `  ${entry.category.padEnd(38)} ${entry.id}\n` +
        `    line ${JSON.stringify(lines)} vs expected [${from},${to}]; route ${JSON.stringify(routes)} vs expected ${entry.route ?? "none"}\n`
    );
  }
}
process.stdout.write("\n");
