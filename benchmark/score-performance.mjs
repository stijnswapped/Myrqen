#!/usr/bin/env node
/**
 * Times the engine on real, large source files and fails on a regression.
 *
 * ## Why a corpus cannot do this job
 *
 * Every corpus case is a few kilobytes, so the whole suite of them runs in about two
 * seconds and any per-file pathology hides inside the rounding. Meanwhile a single
 * 165 KB module took **65 seconds** and scanning this repository took **205**, caused
 * by a lookup in `ast/route-index.ts` that collected every variable declaration in
 * the file once per identifier. Recall, precision and the false-positive rate were
 * all perfect throughout. No existing measurement could see it.
 *
 * So the subject here is deliberately not a corpus: it is this repository's own
 * largest source files, which are ordinary TypeScript of a size real applications
 * reach easily.
 *
 * ## Why a ratchet and not a budget
 *
 * An absolute millisecond budget fails on a slower machine and teaches people to
 * raise the number. A ratchet compares against a recorded baseline with a tolerance
 * wide enough to absorb machine noise, and fails only on a real change of shape —
 * which is what a quadratic reintroduction looks like.
 *
 *   node benchmark/score-performance.mjs
 *   node benchmark/score-performance.mjs --update-baseline
 */
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

const ROOT = path.resolve(import.meta.dirname, "..");
const argv = process.argv.slice(2);
const UPDATE = argv.includes("--update-baseline");
const BASELINE = path.join(ROOT, "benchmark", "performance-baseline.json");
const { scan } = await import(`file://${path.join(ROOT, "packages/scan/dist/index.js")}`);

/**
 * Noise tolerance. Generous on purpose: this is not a benchmark of the machine, and a
 * gate that fires on a busy laptop is a gate somebody deletes. A quadratic lookup
 * reintroduced anywhere in the pre-rule stage costs an order of magnitude, not 60%.
 */
const TOLERANCE = 1.6;

/** The largest real files in the repository, by size, whatever they happen to be. */
async function subjects(limit = 6) {
  const found = [];
  const walk = async (dir) => {
    for (const entry of await fs.readdir(dir, { withFileTypes: true })) {
      if (entry.name.startsWith(".") || entry.name === "node_modules" || entry.name === "dist") continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) await walk(full);
      else if (/\.(ts|tsx|js|mjs)$/.test(entry.name)) {
        const { size } = await fs.stat(full);
        found.push({ file: path.relative(ROOT, full), size });
      }
    }
  };
  for (const dir of ["packages", "apps", "benchmark", "scripts"]) {
    await walk(path.join(ROOT, dir)).catch(() => {});
  }
  return found.sort((a, b) => b.size - a.size).slice(0, limit);
}

/**
 * How fast is this machine, right now?
 *
 * The gate used to compare against an absolute recorded millisecond figure, which
 * made it a machine benchmark wearing a ratchet's clothes: during the work that
 * added this it reported a 2.90x regression on a file whose scan path had not been
 * touched, because a leftover browser suite had the load average at 95. A ratchet
 * that cries wolf is a ratchet people learn to ignore, and this one has caught two
 * real quadratics — its credibility is the asset.
 *
 * So each run measures the machine too, and a recorded timing is scaled by how much
 * slower or faster the machine is than when it was recorded. Deliberately *not*
 * the scanner: a probe that ran the engine would move whenever the engine did, and
 * a change that made everything uniformly slower would hide inside its own control.
 * Integer arithmetic on a fixed input measures the CPU and nothing else.
 *
 * The minimum of several passes, not the mean: contention can only ever make a
 * timing worse, so the fastest pass is the closest estimate of the machine's actual
 * speed available without an idle machine.
 */
function machineProbe(passes = 5) {
  let best = Infinity;
  for (let pass = 0; pass < passes; pass += 1) {
    const started = Date.now();
    let accumulator = 0;
    for (let index = 1; index < 6_000_000; index += 1) {
      accumulator = (accumulator + index * 31) % 1_000_003;
    }
    // Kept so the loop cannot be optimised away entirely.
    if (accumulator === -1) process.stdout.write("");
    best = Math.min(best, Date.now() - started);
  }
  return best;
}

async function timeFile(relative) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-perf-"));
  try {
    const target = path.join(root, "src", path.basename(relative));
    await fs.mkdir(path.dirname(target), { recursive: true });
    await fs.copyFile(path.join(ROOT, relative), target);
    await fs.writeFile(path.join(root, "package.json"), `${JSON.stringify({ name: "perf", version: "1.0.0", type: "module" }, null, 2)}\n`);
    const started = Date.now();
    await scan({ repoRoot: root });
    return Date.now() - started;
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
}

const probeMs = machineProbe();
const results = [];
for (const subject of await subjects()) {
  results.push({ ...subject, ms: await timeFile(subject.file) });
}

const recorded = UPDATE ? null : await fs.readFile(BASELINE, "utf8").then(JSON.parse).catch(() => null);
const byFile = new Map((recorded?.files ?? []).map((entry) => [entry.file, entry]));

process.stdout.write(`\nengine cost on the repository's largest real files (machine probe ${probeMs}ms)\n\n`);
const failures = [];
for (const result of results) {
  const was = byFile.get(result.file);
  // A recorded timing is worth what it was worth on the machine that recorded it.
  const speed = recorded?.probeMs ? probeMs / recorded.probeMs : 1;
  const kb = (result.size / 1024).toFixed(0);
  let note = "";
  if (was) {
    const expected = Math.max(was.ms * speed, 1);
    const ratio = result.ms / expected;
    // Both figures are printed: the raw one because it is what a reader watching
    // the terminal actually feels, and the adjusted one because it is what the gate
    // decides on. When they disagree the machine is busy, and saying so is more use
    // than a bare pass.
    note = `was ${was.ms}ms  ${ratio.toFixed(2)}x`;
    if (Math.abs(speed - 1) > 0.15) note += ` (machine ${speed.toFixed(2)}x)`;
    if (ratio > TOLERANCE) {
      failures.push(
        `${result.file}: ${result.ms}ms against a recorded ${was.ms}ms scaled to ${Math.round(expected)}ms for a machine running ${speed.toFixed(2)}x (${ratio.toFixed(2)}x, tolerance ${TOLERANCE}x)`
      );
      note += "  REGRESSED";
    }
  }
  process.stdout.write(`  ${kb.padStart(5)}KB ${String(result.ms).padStart(7)}ms  ${result.file.padEnd(44)} ${note}\n`);
}

const total = results.reduce((sum, result) => sum + result.ms, 0);
process.stdout.write(`\n  ${String(total).padStart(7)}ms total over ${results.length} file(s)\n`);

if (UPDATE) {
  await fs.writeFile(BASELINE, `${JSON.stringify({ tolerance: TOLERANCE, probeMs, files: results }, null, 2)}\n`, "utf8");
  process.stdout.write(`\nwrote ${path.relative(ROOT, BASELINE)}\n`);
  process.exit(0);
}
/*
 * A missing baseline is a failure, not a pass.
 *
 * This gate runs in CI, and its baseline was untracked for as long as it existed —
 * so on a fresh checkout the file was absent, this branch printed a note, exited 0,
 * and the ratchet reported success without comparing anything. A gate that cannot
 * verify must say so in its exit code; "I could not check" and "I checked and it
 * was fine" are not the same result, and only one of them should let a merge
 * through. `--update-baseline` is the way to create one deliberately.
 */
if (recorded === null) {
  process.stderr.write(
    "\nno performance baseline recorded yet, so nothing was verified — run with --update-baseline to create one\n"
  );
  process.exit(1);
}
if (failures.length > 0) {
  process.stderr.write(`\nperformance gate failed:\n${failures.map((line) => `  - ${line}`).join("\n")}\n`);
  process.exit(1);
}
process.stdout.write("\nperformance gate passed\n");
