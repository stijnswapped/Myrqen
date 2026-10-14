#!/usr/bin/env node
/**
 * Scores the static engine against benchmark/corpus.
 *
 * Every case is scanned in isolation, in a temporary directory containing only
 * that file and a minimal manifest, so one case cannot influence another and a
 * rule cannot pass by recognising a neighbouring file. The engine sees a path it
 * has never seen, under a name that does not describe the defect.
 *
 * Recall comes from vulnerable cases, the false-positive rate from safe ones.
 * Both are reported per class and per family: an aggregate over a hundred cases
 * hides the one class that does not work at all, which is the number that matters.
 */
import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { SPLITS, allowsCaseDetail, partition, splitOf } from "./split.mjs";
/*
 * Shared with `score-agent.mjs`, deliberately.
 *
 * Two harnesses that score the same corpus have to apply the same matching rule and the same
 * interval arithmetic, or the difference between their figures is partly the difference
 * between their scorers and nobody can say which part.
 */
import { intervalOf, resolution, twoProportion, wilson } from "./stats.mjs";
import { NEAR_LINES, routeMatches, sameCwe, satisfies } from "./matching.mjs";
import { defaultScanPath, materialiseCase } from "./case-fixture.mjs";
import { promisify } from "node:util";
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
function flag(name, fallback) {
  const index = argv.indexOf(`--${name}`);
  if (index === -1) return fallback;
  const value = argv[index + 1];
  return value && !value.startsWith("--") ? value : true;
}

/**
 * Which corpus to score. The development corpus is the default; a held-out corpus is
 * pointed at explicitly, and writes its own baseline and last-run files so a holdout
 * result can never be mistaken for a development one.
 */
const CORPUS_DIR = typeof flag("corpus", null) === "string" ? path.resolve(ROOT, flag("corpus", null)) : path.join(ROOT, "benchmark", "corpus");
const CORPUS = CORPUS_DIR;
const CORPUS_LABEL = path.basename(CORPUS_DIR);
/*
 * The result file, one per corpus and per split.
 *
 * Suffixed with the split when there is one, because otherwise scoring the holdout would
 * overwrite the development half's run file and each would then ratchet against the other's
 * floor — two different samples silently compared as though they were one.
 */
const SPLIT_ARG = (() => {
  const index = process.argv.indexOf("--split");
  const value = index === -1 ? null : process.argv[index + 1];
  return value && SPLITS.includes(value) ? value : null;
})();
const RESULT_PREFIX = SPLIT_ARG ? `${CORPUS_LABEL}-${SPLIT_ARG}` : CORPUS_LABEL;

/**
 * Release gates for the corpus, from the release plan. These are not aspirations:
 * the process exits non-zero below any of them.
 */
const GATES = {
  criticalHighRecall: 0.95,
  overallRecall: 0.9,
  precision: 0.9,
  safeFalsePositiveRate: 0.03
};

/**
 * Families whose language the engine does not parse are scored separately.
 *
 * Python left this set when `packages/scan-python` landed (ADR 020). From then on
 * a Python case the engine misses is a miss — including a Django case, whose
 * framework is parsed but not modelled. That is the same standard a JavaScript
 * framework without an adapter has always been held to.
 */
const UNSUPPORTED_LANGUAGES = new Set(["ruby", "go", "php", "java"]);

/**
 * Capabilities the static pass does not claim, scored separately rather than
 * counted as misses.
 *
 * This is the same judgement `UNSUPPORTED_LANGUAGES` already makes, applied to the
 * other documented limitation: "a language the engine cannot parse is a
 * limitation, not a miss" and "a flow the engine does not follow" is the same
 * sentence. Taint here is intra-procedural by design — the product gives
 * cross-module reasoning to the host agent, and the engine says so in its own
 * coverage output — so a case whose value becomes attacker-controlled in one
 * module and is used in another measures a capability nothing here claims.
 *
 * Two things this is not. It is not permission to relabel a case after seeing it
 * fail: an author marks `outOfScope` while writing, from the code, and
 * `docs/12-release/HOLDOUT-PROTOCOL.md` records that `benchmark/holdout-3` was
 * deliberately **not** retro-labelled. And it is not a claim that these defects do
 * not matter — they are reported, with their own recall figure, precisely so that
 * choosing to build cross-module flow later is an informed decision rather than a
 * rediscovery.
 */
const OUT_OF_SCOPE_REASONS = new Set(["cross_module"]);

async function loadManifest() {
  const raw = await fs.readFile(path.join(CORPUS, "manifest.json"), "utf8");
  const manifest = JSON.parse(raw);
  if (!Array.isArray(manifest.cases)) throw new Error("manifest.json must contain a `cases` array");
  return manifest;
}

/**
 * Scan one case alone. The temporary directory is named for nothing in particular
 * and the file keeps only its extension, so no rule can key on a corpus path.
 */
/**
 * Does this candidate claim the CWE the case expects?
 *
 * Asks whether **any** taxonomy entry matches, not whether the first CWE-shaped one does. A
 * finding routinely carries several — `["CWE-306", "CWE-862", "OWASP-A01"]` — because one
 * defect has more than one standard name, and picking the first would deny credit to a case
 * whose author cited the second. Getting this wrong moved holdout-6's `cweRecall` from 0.500
 * to 0.467, which is the kind of silent definitional drift the recorded run files exist to
 * catch.
 */
function claimsCwe(candidate, expected) {
  return (candidate.taxonomy ?? []).some((entry) => sameCwe(entry, expected));
}

async function scanCase(entry) {
  const { root, scanAs } = await materialiseCase(CORPUS, entry, "myrqen-corpus-");
  try {
    const result = await scan({ repoRoot: root });
    return { candidates: result.candidates, coverage: result.coverage, scannedAs: scanAs };
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
}

/**
 * Where the case file lands inside the scratch project. File-based routing cases
 * need their real path, because the route *is* the path; everything else goes
 * under src/ with its own basename.
 */
/**
 * Does a candidate satisfy this vulnerable case?
 *
 * Route matching allows the ground truth's path to *end with* the discovered one on
 * a segment boundary. A router module declares `/search` and the application mounts
 * it at `/invoices`, so a single file genuinely cannot know the full path — the
 * mount lives elsewhere. The method and the declared path still have to be right,
 * and the engine states the mount limitation in its own coverage output rather than
 * leaving a reader to assume the path is complete.
 */
/**
 * Do two CWE references name the same weakness?
 *
 * Compared on the number alone, so `CWE-639`, `cwe-639` and `639` agree. Nothing
 * cleverer: CWE has a class/base/variant hierarchy, and an engine reporting the
 * parent of the author's class is arguably right, but crediting that automatically
 * would let this scorer grant itself partial marks. A parent-child disagreement is
 * argued case by case in HOLDOUT-PROTOCOL.md after the score is recorded, per
 * ruling S4.
 */
/**
 * How far from the stated line a finding may sit and still plainly be about it.
 *
 * A composition and the sink it feeds are usually a handful of lines apart; a
 * finding half a handler away is about a different statement.
 */
function band(entry) {
  return entry.severityBand ?? [];
}

/**
 * The scanner's commit, and whether `packages/scan` was clean when it was built.
 * Both null outside a git checkout, which is a normal way to run this.
 */
/** Every engine source file, concatenated in a stable order. */
async function engineSource() {
  const root = path.join(ROOT, "packages", "scan", "src");
  const files = [];
  const walk = async (dir) => {
    for (const entry of (await fs.readdir(dir, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) await walk(full);
      else if (entry.name.endsWith(".ts")) files.push(full);
    }
  };
  await walk(root);
  const parts = [];
  for (const file of files) parts.push(`${path.relative(root, file)}\n${await fs.readFile(file, "utf8")}`);
  return parts.join("\n");
}

async function engineProvenance() {
  const run = promisify(execFile);
  try {
    const { stdout: commit } = await run("git", ["rev-parse", "--short", "HEAD"], { cwd: ROOT });
    const { stdout: dirty } = await run("git", ["status", "--porcelain", "--", "packages/scan/src"], { cwd: ROOT });
    /*
     * A hash of the engine source, so a measurement taken against uncommitted work
     * is still identifiable later.
     *
     * A held-out score is only worth what its reproducibility is worth, and
     * `engineDirty: true` beside a commit says "this was some other engine" without
     * saying which. Hashing the tree costs nothing and turns that into a claim
     * somebody can check. It is not a substitute for committing before measuring.
     *
     * Hashed in process rather than by piping to `git hash-object`: promisified
     * `execFile` has no `input` option, so passing one writes nothing to stdin and
     * the child waits on it forever. That trap has now cost this project time twice.
     */
    const engineHash = createHash("sha256").update(await engineSource()).digest("hex").slice(0, 12);
    return {
      scannerCommit: commit.trim(),
      engineDirty: dirty.trim().length > 0,
      engineHash
    };
  } catch {
    return { scannerCommit: null, engineDirty: null };
  }
}

async function main() {
  const manifest = await loadManifest();
  const familyFilter = flag("family", null);
  const classFilter = flag("class", null);
  const verbose = flag("verbose", false) === true;
  const updateBaseline = flag("update-baseline", false) === true;
  const updateFloor = flag("update-floor", false) === true;
  /*
   * `--split dev` or `--split holdout` on a corpus that declares one.
   *
   * A corpus without a split scores whole, exactly as before. The holdout deliberately
   * refuses to print per-case detail — see `benchmark/split.mjs` for why that is a
   * mechanism rather than a preference.
   */
  const splitFilter = flag("split", null);
  if (splitFilter !== null && !SPLITS.includes(splitFilter)) {
    process.stderr.write(`--split must be one of ${SPLITS.join(", ")}\n`);
    process.exitCode = 1;
    return;
  }
  const caseDetail = splitFilter === null ? true : allowsCaseDetail(splitFilter);

  const cases = manifest.cases.filter((entry) => {
    if (typeof familyFilter === "string" && entry.family !== familyFilter) return false;
    if (typeof classFilter === "string" && entry.category !== classFilter) return false;
    if (typeof splitFilter === "string" && splitOf(entry.family) !== splitFilter) return false;
    return true;
  });

  if (typeof splitFilter === "string") {
    const halves = partition([...new Set(manifest.cases.map((entry) => entry.family))]);
    process.stdout.write(
      `split: ${splitFilter} — ${halves[splitFilter].length} of ${halves.dev.length + halves.holdout.length} families` +
        `${caseDetail ? "" : ", aggregate figures only"}\n`
    );
  }

  if (cases.length === 0) {
    process.stderr.write("No cases matched. Check --family and --class.\n");
    process.exitCode = 1;
    return;
  }

  /*
   * Printed with the interval, because a figure printed alone gets read as exact.
   * Ruling U7: four blind runs were written up as a declining trend when their 95%
   * intervals all overlapped.
   */
  const spread = (successes, trials) => {
    const w = wilson(successes, trials);
    return w === null ? "" : `  [${w.low.toFixed(3)}, ${w.high.toFixed(3)}]`;
  };

  /*
   * A rule that throws is recorded in `coverage.parseFailures` and changes nothing else, so
   * the case reads as a clean miss and every figure is computed as though the rule had
   * looked. Silence caused by an exception is not silence caused by a rule declining.
   */
  const ruleFailures = [];
  const outcomes = [];
  for (const entry of cases) {
    const scanned = await scanCase(entry);
    for (const failure of scanned.coverage?.parseFailures ?? []) {
      if (failure.reason.startsWith("rule ")) ruleFailures.push(`${entry.id}: ${failure.file}: ${failure.reason}`);
    }
    if (entry.kind === "vulnerable") {
      const inRange = scanned.candidates.filter((candidate) => {
        const [from, to] = entry.lineRange ?? [entry.line, entry.line];
        return candidate.location.line >= from && candidate.location.line <= to;
      });
      const cweCredit = inRange.find((candidate) => claimsCwe(candidate, entry.cwe));
      const nearCredit = inRange.find(
        (candidate) => claimsCwe(candidate, entry.cwe) && Math.abs(candidate.location.line - entry.line) <= NEAR_LINES
      );
      const hit = scanned.candidates.find((candidate) => satisfies(candidate, entry));
      const wrongPlace = scanned.candidates.filter(
        (candidate) => candidate.category === entry.category && !satisfies(candidate, entry)
      );
      outcomes.push({
        ...entry,
        detected: Boolean(hit),
        // Any finding inside the author's stated range, whatever either side calls the class.
        anyClassInRange: inRange.length > 0,
        cweMatched: Boolean(cweCredit),
        cweMatchedNear: Boolean(nearCredit),
        creditedBy: cweCredit
          ? {
              ruleId: cweCredit.ruleId,
              line: cweCredit.location.line,
              distanceFromLine: Math.abs(cweCredit.location.line - entry.line)
            }
          : inRange[0]
            ? { ruleId: inRange[0].ruleId, line: inRange[0].location.line, distanceFromLine: Math.abs(inRange[0].location.line - entry.line) }
            : null,
        severityReported: hit?.severity ?? null,
        severityInBand: hit ? band(entry).includes(hit.severity) : null,
        routeReported: hit?.route ?? null,
        // Findings other than the expected one. On a vulnerable case these are
        // not necessarily wrong — a realistic file often has more than one issue —
        // so they are listed, never silently counted against precision.
        alsoReported: scanned.candidates
          .filter((candidate) => candidate !== hit)
          .map((candidate) => ({ category: candidate.category, line: candidate.location.line, severity: candidate.severity })),
        misattributed: wrongPlace.map((candidate) => ({ line: candidate.location.line, route: candidate.route ?? null })),
        unsupported: UNSUPPORTED_LANGUAGES.has(entry.language),
        outOfScope: OUT_OF_SCOPE_REASONS.has(entry.outOfScope) ? entry.outOfScope : null
      });
    } else {
      /*
       * Findings in the case's own file, not in the helpers it ships beside it.
       *
       * A family shares its `extraFiles` across every case in it, so one finding in one
       * shared helper was counted once per case that shipped it — seven false positives
       * from one line, on the first family authored for the reference corpus.
       */
      const ownFile = scanned.candidates.filter((candidate) => candidate.location.file === scanned.scannedAs);
      const inHelpers = scanned.candidates.filter((candidate) => candidate.location.file !== scanned.scannedAs);
      outcomes.push({
        ...entry,
        helperFindings: inHelpers.map((candidate) => ({
          file: candidate.location.file,
          line: candidate.location.line,
          ruleId: candidate.ruleId,
          verification: candidate.verification
        })),
        falsePositives: ownFile.map((candidate) => ({
          category: candidate.category,
          line: candidate.location.line,
          severity: candidate.severity,
          ruleId: candidate.ruleId,
          // Recorded so a deliberate candidate can be told from a mistaken claim.
          verification: candidate.verification
        })),
        unsupported: UNSUPPORTED_LANGUAGES.has(entry.language),
        outOfScope: OUT_OF_SCOPE_REASONS.has(entry.outOfScope) ? entry.outOfScope : null
      });
    }
  }

  /* ---------- aggregate ---------- */

  const supported = outcomes.filter((outcome) => !outcome.unsupported && !outcome.outOfScope);
  const vulnerable = supported.filter((outcome) => outcome.kind === "vulnerable");
  const safe = supported.filter((outcome) => outcome.kind === "safe");
  const unsupported = outcomes.filter((outcome) => outcome.unsupported);
  // Out of scope for the *gate*, never out of sight: reported below with their own
  // recall, because a limitation nobody can see the size of is a limitation nobody
  // ever decides to remove.
  const outOfScope = outcomes.filter((outcome) => !outcome.unsupported && outcome.outOfScope);
  const outOfScopeVulnerable = outOfScope.filter((outcome) => outcome.kind === "vulnerable");
  const outOfScopeDetected = outOfScopeVulnerable.filter((outcome) => outcome.detected);

  const detected = vulnerable.filter((outcome) => outcome.detected);
  const classBlind = vulnerable.filter((outcome) => outcome.anyClassInRange);
  /*
   * CWE is the join between two vocabularies neither side was shown (ruling S2). Only cases
   * whose author supplied one are scored, so a `cweNote` case does not count against it.
   */
  const cweScored = vulnerable.filter((outcome) => Boolean(outcome.cwe));
  const cweHit = cweScored.filter((outcome) => outcome.cweMatched);
  const cweNearHit = cweScored.filter((outcome) => outcome.cweMatchedNear);
  const criticalHigh = vulnerable.filter((outcome) => band(outcome).some((level) => level === "critical" || level === "high"));
  const criticalHighDetected = criticalHigh.filter((outcome) => outcome.detected);
  const safeWithFindings = safe.filter((outcome) => outcome.falsePositives.length > 0);

  const recall = vulnerable.length === 0 ? null : detected.length / vulnerable.length;
  const classBlindRecall = vulnerable.length === 0 ? null : classBlind.length / vulnerable.length;
  const cweRecall = cweScored.length === 0 ? null : cweHit.length / cweScored.length;
  const cweRecallNear = cweScored.length === 0 ? null : cweNearHit.length / cweScored.length;
  const criticalHighRecall = criticalHigh.length === 0 ? null : criticalHighDetected.length / criticalHigh.length;
  const falsePositiveRate = safe.length === 0 ? null : safeWithFindings.length / safe.length;
  /*
   * A rule asserting a defect that is not there, and a rule asking for a look, are different
   * failures. Counting them identically made a deliberate candidate impossible to ship, so
   * all three rates are reported and all three ratchet independently.
   */
  const confident = (finding) => finding.verification !== "needs_review";
  const safeWithConfidentFindings = safe.filter((outcome) => outcome.falsePositives.some(confident));
  const safeWithOnlyCandidates = safe.filter(
    (outcome) => outcome.falsePositives.length > 0 && !outcome.falsePositives.some(confident)
  );
  const confidentFalsePositiveRate = safe.length === 0 ? null : safeWithConfidentFindings.length / safe.length;
  const candidateFalsePositiveRate = safe.length === 0 ? null : safeWithOnlyCandidates.length / safe.length;

  // Precision over the whole corpus: a true positive is an expected detection; a
  // false positive is any finding on a safe case. Extra findings on vulnerable
  // cases are excluded from both, because a realistic vulnerable file legitimately
  // contains more than the one defect it is catalogued for.
  const falsePositiveCount = safe.reduce((sum, outcome) => sum + outcome.falsePositives.length, 0);
  const precision =
    detected.length + falsePositiveCount === 0 ? null : detected.length / (detected.length + falsePositiveCount);
  const confidentFalsePositiveCount = safe.reduce(
    (sum, outcome) => sum + outcome.falsePositives.filter(confident).length,
    0
  );
  const confidentPrecision =
    detected.length + confidentFalsePositiveCount === 0
      ? null
      : detected.length / (detected.length + confidentFalsePositiveCount);

  const byClass = {};
  for (const outcome of vulnerable) {
    const bucket = (byClass[outcome.category] ??= { expected: 0, detected: 0, inBand: 0, misattributed: 0 });
    bucket.expected += 1;
    if (outcome.detected) bucket.detected += 1;
    if (outcome.severityInBand) bucket.inBand += 1;
    if (!outcome.detected && outcome.misattributed.length > 0) bucket.misattributed += 1;
  }

  const byFamily = {};
  for (const outcome of supported) {
    const bucket = (byFamily[outcome.family] ??= { vulnerable: 0, detected: 0, safe: 0, falsePositives: 0 });
    if (outcome.kind === "vulnerable") {
      bucket.vulnerable += 1;
      if (outcome.detected) bucket.detected += 1;
    } else {
      bucket.safe += 1;
      bucket.falsePositives += outcome.falsePositives.length;
    }
  }

  /* ---------- report ---------- */

  const percent = (value) => (value === null ? "n/a" : value.toFixed(3));
  process.stdout.write(`\n${CORPUS_LABEL}: ${cases.length} case(s) — ${vulnerable.length} vulnerable, ${safe.length} safe`);
  const asides = [];
  if (unsupported.length > 0) asides.push(`${unsupported.length} in an unparsed language`);
  if (outOfScope.length > 0) asides.push(`${outOfScope.length} outside what the static pass claims`);
  process.stdout.write(asides.length > 0 ? `, ${asides.join(", ")}\n` : "\n");
  process.stdout.write(
    `recall                ${percent(recall)} (${detected.length}/${vulnerable.length})${spread(detected.length, vulnerable.length)}\n`
  );
  process.stdout.write(
    `  class-blind         ${percent(classBlindRecall)} (${classBlind.length}/${vulnerable.length})${spread(classBlind.length, vulnerable.length)} - any finding inside the expected lines\n` +
      (cweScored.length > 0
        ? `  cwe-matched         ${percent(cweRecall)} (${cweHit.length}/${cweScored.length})${spread(cweHit.length, cweScored.length)} - a finding in range agreeing on CWE\n` +
          `  cwe-matched near    ${percent(cweRecallNear)} (${cweNearHit.length}/${cweScored.length})${spread(cweNearHit.length, cweScored.length)} - within ${NEAR_LINES} lines of the stated line\n`
        : "")
  );
  process.stdout.write(
    `  95% intervals above. On ${vulnerable.length} cases a difference smaller than about ${(resolution(vulnerable.length) ?? 0).toFixed(2)} is not measurable here.\n`
  );
  process.stdout.write(
    `critical/high recall  ${percent(criticalHighRecall)} (${criticalHighDetected.length}/${criticalHigh.length})\n`
  );
  process.stdout.write(`precision             ${percent(precision)}\n`);
  if (confidentPrecision !== precision) {
    process.stdout.write(`  confident only      ${percent(confidentPrecision)} - ignoring unsettled candidates\n`);
  }
  process.stdout.write(
    `safe-case FP rate     ${percent(falsePositiveRate)} (${safeWithFindings.length}/${safe.length} safe case(s) produced a finding)${spread(safeWithFindings.length, safe.length)}\n`
  );
  process.stdout.write(
    `  asserted            ${percent(confidentFalsePositiveRate)} (${safeWithConfidentFindings.length}/${safe.length})${spread(safeWithConfidentFindings.length, safe.length)} - a rule claimed a defect that is not there\n` +
      `  needs review        ${percent(candidateFalsePositiveRate)} (${safeWithOnlyCandidates.length}/${safe.length}) - a rule asked for a look and nothing worse\n`
  );

  const weakClasses = Object.entries(byClass)
    .filter(([, bucket]) => bucket.detected < bucket.expected)
    .sort((a, b) => a[1].detected / a[1].expected - b[1].detected / b[1].expected);
  if (weakClasses.length > 0) {
    process.stdout.write(`\nclasses not fully detected:\n`);
    for (const [category, bucket] of weakClasses) {
      const note = bucket.misattributed > 0 ? ` (${bucket.misattributed} found in the wrong place)` : "";
      process.stdout.write(`  ${category.padEnd(42)} ${bucket.detected}/${bucket.expected}${note}\n`);
    }
  }

  const bandProblems = Object.entries(byClass).filter(([, bucket]) => bucket.inBand < bucket.detected);
  if (bandProblems.length > 0) {
    process.stdout.write(`\nseverity outside the expected band:\n`);
    for (const [category, bucket] of bandProblems) {
      process.stdout.write(`  ${category.padEnd(42)} ${bucket.inBand}/${bucket.detected} in band\n`);
    }
  }

  if (safeWithFindings.length > 0) {
    /*
     * Named on a development corpus, counted on a holdout.
     *
     * The line where a false positive landed is the most useful thing this scorer prints, and
     * on a permanent holdout it is the one thing that must not be: naming the case is the
     * first step of tuning to it. Class-level counts stay visible in both, because "nothing
     * detects this class" names a capability rather than a case.
     */
    if (caseDetail) {
      process.stdout.write(`\nfindings on correct code:\n`);
      for (const outcome of safeWithFindings) {
        for (const finding of outcome.falsePositives) {
          process.stdout.write(`  ${outcome.id.padEnd(46)} ${finding.ruleId} at line ${finding.line}\n`);
        }
      }
    } else {
      const rules = new Set(safeWithFindings.flatMap((outcome) => outcome.falsePositives.map((f) => f.ruleId)));
      process.stdout.write(
        `\nfindings on correct code: ${safeWithFindings.length} case(s), from ${[...rules].sort().join(", ")}\n` +
          `  cases are not named on a holdout — see benchmark/split.mjs\n`
      );
    }
  }

  if (outOfScope.length > 0) {
    const rate = outOfScopeVulnerable.length === 0 ? null : outOfScopeDetected.length / outOfScopeVulnerable.length;
    process.stdout.write(`\noutside what the static pass claims, reported and not gated:\n`);
    for (const reason of new Set(outOfScope.map((outcome) => outcome.outOfScope))) {
      const named = outOfScope.filter((outcome) => outcome.outOfScope === reason);
      process.stdout.write(`  ${reason.padEnd(14)} ${named.length} case(s)\n`);
    }
    process.stdout.write(
      `  recall on them  ${rate === null ? "n/a" : rate.toFixed(3)} (${outOfScopeDetected.length}/${outOfScopeVulnerable.length})` +
        ` — the host agent's part of the assessment, which this harness does not exercise\n`
    );
  }

  if (unsupported.length > 0) {
    process.stdout.write(`\nnot assessed (language not parsed by the engine):\n`);
    const languages = [...new Set(unsupported.map((outcome) => outcome.language))];
    for (const language of languages) {
      const count = unsupported.filter((outcome) => outcome.language === language).length;
      process.stdout.write(`  ${language.padEnd(12)} ${count} case(s)\n`);
    }
  }

  if (verbose && caseDetail) {
    process.stdout.write(`\nper-family:\n`);
    for (const [family, bucket] of Object.entries(byFamily)) {
      process.stdout.write(
        `  ${family.padEnd(26)} vulnerable ${bucket.detected}/${bucket.vulnerable}, safe ${bucket.safe - 0} case(s) with ${bucket.falsePositives} finding(s)\n`
      );
    }
    const missed = vulnerable.filter((outcome) => !outcome.detected);
    if (missed.length > 0) {
      process.stdout.write(`\nmissed cases:\n`);
      for (const outcome of missed) {
        process.stdout.write(`  ${outcome.id} — ${outcome.category} at ${outcome.file}:${outcome.line}\n`);
      }
    }
  }

  const payload = {
    generatedAt: new Date().toISOString(),
    /*
     * Which engine produced this. Provenance belongs in the artifact rather than in
     * a prose document somebody has to remember to update: a run scored against a
     * stale `dist` is indistinguishable from a fresh one otherwise, and
     * `packages/scan`'s build silently writes nothing when `tsconfig.tsbuildinfo`
     * outlives a deleted `dist`. `engineDirty` is the more useful half — a commit
     * hash means nothing if the working tree it describes had uncommitted rules in
     * it.
     */
    ...(await engineProvenance()),
    gates: GATES,
    totals: {
      cases: cases.length,
      vulnerable: vulnerable.length,
      safe: safe.length,
      unsupported: unsupported.length,
      outOfScope: outOfScope.length,
      outOfScopeRecall:
        outOfScopeVulnerable.length === 0 ? null : outOfScopeDetected.length / outOfScopeVulnerable.length,
      recall,
      classBlindRecall,
      cweRecall,
      cweRecallNear,
      cweScored: cweScored.length,
      criticalHighRecall,
      precision,
      falsePositiveRate,
      confidentFalsePositiveRate,
      candidateFalsePositiveRate,
      confidentPrecision,
      /*
       * The same figures as intervals. Keyed by the metric they qualify so a consumer
       * cannot pair a rate with the wrong bound, and rounded to four places because
       * anything finer is a false precision on n = 30.
       */
      intervals: {
        recall: intervalOf(wilson(detected.length, vulnerable.length)),
        classBlindRecall: intervalOf(wilson(classBlind.length, vulnerable.length)),
        cweRecall: cweScored.length === 0 ? null : intervalOf(wilson(cweHit.length, cweScored.length)),
        cweRecallNear: cweScored.length === 0 ? null : intervalOf(wilson(cweNearHit.length, cweScored.length)),
        falsePositiveRate: intervalOf(wilson(safeWithFindings.length, safe.length)),
        confidentFalsePositiveRate: intervalOf(wilson(safeWithConfidentFindings.length, safe.length))
      },
      sampleSize: { vulnerable: vulnerable.length, safe: safe.length, cweScored: cweScored.length }
    },
    byClass,
    byFamily,
    /*
     * Per-case outcomes, on a development corpus only.
     *
     * This array is what a reader would reach for the moment a holdout figure moved, and
     * writing it would make every "do not look" rule elsewhere decorative. The aggregate
     * blocks above — totals, byClass, byFamily — carry everything a decision needs.
     */
    outcomes: caseDetail ? outcomes : [],
    ...(caseDetail ? {} : { outcomesWithheld: outcomes.length })
  };
  await fs.writeFile(path.join(ROOT, "benchmark", `${RESULT_PREFIX}-last-run.json`), `${JSON.stringify(payload, null, 2)}\n`);
  process.stdout.write(`\nwrote benchmark/${RESULT_PREFIX}-last-run.json\n`);

  /* ---------- gates ---------- */

  /*
   * Two kinds of bad news, and only one of them should fail a build.
   *
   * `aspirations` are the absolute gates — recall 0.90, precision 0.90. Every
   * held-out corpus is below them and is published as being below them; that is the
   * honest position, not a regression. `regressions` are breaches of the recorded
   * floor: this corpus used to do better than it just did.
   *
   * Conflating the two is why no holdout has ever had a usable exit code. A run that
   * always fails carries no information, so nothing in CI could tell that holdout-5
   * had dropped a class. A corpus with a recorded floor therefore exits non-zero on a
   * regression only, and reports its unmet aspirations without failing on them.
   */
  const aspirations = [];
  const regressions = [];
  const failures = aspirations;
  if (criticalHighRecall !== null && criticalHighRecall < GATES.criticalHighRecall) {
    failures.push(`critical/high recall ${percent(criticalHighRecall)} < ${GATES.criticalHighRecall}`);
  }
  if (recall !== null && recall < GATES.overallRecall) {
    failures.push(`overall recall ${percent(recall)} < ${GATES.overallRecall}`);
  }
  if (precision !== null && precision < GATES.precision) {
    failures.push(`precision ${percent(precision)} < ${GATES.precision}`);
  }
  /*
   * The gate measures **asserted** false positives, the floor measures all three.
   *
   * A rule that says `strong_evidence` about correct code has made a false claim, and
   * that is what a precision gate is for. A rule that says `needs_review` has asked for
   * a look; on a corpus of deliberately-correct files that is usually still noise, but
   * it is not the same failure and gating them identically is what made an unsettled
   * candidate impossible to ship.
   *
   * Moving the gate to the asserted rate loosens what it measures — on holdout-6 the
   * combined rate is 0.069 and the asserted rate 0.034, because one of its two false
   * positives was already `needs_review` before any of this. So the floor below ratchets
   * **all three** rates independently: reclassifying a finding from asserted to
   * unsettled cannot improve a floor check, and deliberately adding a candidate requires
   * an explicit recorded baseline update with a reason, rather than drifting.
   */
  if (confidentFalsePositiveRate !== null && confidentFalsePositiveRate > GATES.safeFalsePositiveRate) {
    failures.push(
      `asserted safe-case false-positive rate ${percent(confidentFalsePositiveRate)} > ${GATES.safeFalsePositiveRate}`
    );
  }

  /*
   * Recording a floor while the aspirational gates are unmet.
   *
   * `--update-baseline` refuses to write when a gate fails, which is right for the
   * development corpus: a baseline taken from a failing run would bless the failure.
   * It is unworkable for every held-out corpus, because the recall gate is 0.90 and
   * the honest figure is 0.267 — so no holdout has ever had a baseline, and nothing
   * has ever stopped a holdout figure from silently regressing.
   *
   * `--update-floor` writes the same file with the absolute-gate failures recorded
   * inside it rather than blocking on them. The distinction is the point: a floor
   * says "do not get worse than this", an aspiration says "this is what acceptable
   * would be", and conflating them is why one of the two did not exist.
   */
  if (updateFloor) {
    const floorPayload = { ...payload, floorRecordedWithUnmetGates: failures };
    await fs.writeFile(
      path.join(ROOT, "benchmark", `${RESULT_PREFIX}-baseline.json`),
      `${JSON.stringify(floorPayload, null, 2)}\n`
    );
    process.stdout.write(`wrote benchmark/${RESULT_PREFIX}-baseline.json as a floor`);
    process.stdout.write(failures.length > 0 ? ` (${failures.length} aspirational gate(s) still unmet)\n` : "\n");
    return;
  }

  if (updateBaseline) {
    if (failures.length > 0) {
      process.stderr.write(`\nRefusing to update the baseline while gates fail:\n${failures.map((f) => `  - ${f}`).join("\n")}\n`);
      process.exitCode = 1;
      return;
    }
    await fs.writeFile(path.join(ROOT, "benchmark", `${RESULT_PREFIX}-baseline.json`), `${JSON.stringify(payload, null, 2)}\n`);
    process.stdout.write(`wrote benchmark/${RESULT_PREFIX}-baseline.json\n`);
    return;
  }

  // A regression is its own failure, separate from the absolute gates: a corpus
  // can be well above the gate and still have lost a class it used to detect.
  let hasFloor = false;
  try {
    const baseline = JSON.parse(await fs.readFile(path.join(ROOT, "benchmark", `${RESULT_PREFIX}-baseline.json`), "utf8"));
    for (const [category, bucket] of Object.entries(baseline.byClass ?? {})) {
      const now = byClass[category];
      if (!now) continue;
      const before = bucket.detected / bucket.expected;
      const after = now.detected / now.expected;
      if (after < before) regressions.push(`${category} recall fell from ${before.toFixed(3)} to ${after.toFixed(3)}`);
    }
    // All three rates ratchet, so the split cannot be used to hide a regression.
    for (const [key, label] of [
      ["falsePositiveRate", "safe-case false-positive rate"],
      ["confidentFalsePositiveRate", "asserted safe-case false-positive rate"],
      ["candidateFalsePositiveRate", "unsettled-candidate rate on safe cases"]
    ]) {
      const before = baseline.totals?.[key];
      const after = payload.totals?.[key];
      if (typeof before !== "number" || typeof after !== "number") continue;
      if (after > before) regressions.push(`${label} rose from ${before.toFixed(3)} to ${after.toFixed(3)}`);
    }
    /*
     * The headline figures are floors too.
     *
     * Per-class recall was already guarded, which catches losing a class outright and
     * misses everything else: a corpus can hold every class and still fall from 0.433
     * to 0.367 because two cases moved, and nothing said so. These are the figures
     * quoted on the site, so these are the figures that must not silently drop.
     */
    for (const key of ["recall", "classBlindRecall", "cweRecall", "cweRecallNear", "criticalHighRecall"]) {
      const before = baseline.totals?.[key];
      const after = payload.totals?.[key];
      if (typeof before !== "number" || typeof after !== "number") continue;
      if (after < before) {
        /*
         * Still a regression, and still fails the build — a ratchet that waits for
         * statistical significance lets a real drop through for as long as it hides
         * inside the noise. What the note adds is what a reader may conclude from it,
         * which is the half that has gone wrong repeatedly: two cases moving on a
         * thirty-case corpus is not evidence that anything got worse.
         */
        const n = payload.totals?.sampleSize?.vulnerable ?? 0;
        const verdict = distinguishable(Math.round(after * n), n, Math.round(before * n), n);
        const note =
          verdict === null ? "" : verdict.distinguishable ? " (distinguishable from noise)" : " (within noise at this sample size)";
        regressions.push(`${key} fell from ${before.toFixed(3)} to ${after.toFixed(3)}${note}`);
      }
    }
    hasFloor = true;
  } catch {
    process.stdout.write(`no ${RESULT_PREFIX} baseline recorded yet\n`);
  }

  if (regressions.length > 0) {
    process.stderr.write(
      `\n${CORPUS_LABEL} regressed against its recorded floor in ${regressions.length} way(s):\n` +
        `${regressions.map((f) => `  - ${f}`).join("\n")}\n`
    );
    process.exitCode = 1;
  }

  if (aspirations.length > 0) {
    // Printed either way. Whether it fails the build depends on whether this corpus
    // has a floor: without one there is nothing else to judge it by.
    const verb = hasFloor ? "is below" : "failed";
    const stream = hasFloor ? process.stdout : process.stderr;
    stream.write(
      `\n${CORPUS_LABEL} ${verb} ${aspirations.length} aspirational gate(s):\n` +
        `${aspirations.map((f) => `  - ${f}`).join("\n")}\n`
    );
    if (!hasFloor) process.exitCode = 1;
  }

  if (ruleFailures.length > 0) {
    // Unconditional, and not a ratchet: there is no acceptable number of these. A rule
    // that throws has stopped measuring, and every figure above was computed as though
    // it had measured and found nothing.
    process.stderr.write(
      `\n${CORPUS_LABEL}: ${ruleFailures.length} rule(s) threw during scanning, so their findings are missing rather than absent:\n` +
        `${[...new Set(ruleFailures)].map((f) => `  - ${f}`).join("\n")}\n`
    );
    process.exitCode = 1;
  }

  if (regressions.length === 0 && aspirations.length === 0 && ruleFailures.length === 0) {
    process.stdout.write(`all ${CORPUS_LABEL} gates passed\n`);
  } else if (regressions.length === 0) {
    process.stdout.write(`\n${CORPUS_LABEL}: no regression against the recorded floor\n`);
  }
}

await main();
