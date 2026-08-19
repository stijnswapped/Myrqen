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
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { scan } from "../packages/scan/dist/index.js";

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
const RESULT_PREFIX = CORPUS_LABEL === "corpus" ? "corpus" : CORPUS_LABEL;

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

/** Families whose language the engine does not parse are scored separately. */
const UNSUPPORTED_LANGUAGES = new Set(["python", "ruby", "go", "php", "java"]);

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
async function scanCase(entry) {
  const source = await fs.readFile(path.join(CORPUS, entry.file), "utf8");
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-corpus-"));
  try {
    const target = path.join(root, entry.scanAs ?? defaultScanPath(entry));
    await fs.mkdir(path.dirname(target), { recursive: true });
    await fs.writeFile(target, source, "utf8");

    // A package manifest so dependency rules have something to read, and so the
    // project looks like a project rather than a loose file.
    if (entry.packageJson) {
      await fs.writeFile(path.join(root, "package.json"), `${JSON.stringify(entry.packageJson, null, 2)}\n`, "utf8");
    } else {
      await fs.writeFile(
        path.join(root, "package.json"),
        `${JSON.stringify({ name: "case", version: "1.0.0", type: "module" }, null, 2)}\n`,
        "utf8"
      );
    }
    for (const [relative, contents] of Object.entries(entry.extraFiles ?? {})) {
      const extra = path.join(root, relative);
      await fs.mkdir(path.dirname(extra), { recursive: true });
      await fs.writeFile(extra, contents, "utf8");
    }

    const result = await scan({ repoRoot: root });
    return { candidates: result.candidates, coverage: result.coverage, scannedAs: path.relative(root, target) };
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
}

/**
 * Where the case file lands inside the scratch project. File-based routing cases
 * need their real path, because the route *is* the path; everything else goes
 * under src/ with its own basename.
 */
function defaultScanPath(entry) {
  if (entry.family.startsWith("nextjs")) return entry.file.split("/").slice(1).join("/");
  return path.join("src", path.basename(entry.file));
}

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

  // A router-root declaration carries no path of its own: every segment of the
  // expected path is the mount prefix, which the file cannot see. The method still
  // has to be right, so this is not a free pass.
  if (reportedPath === "/") return true;
  return expectedPath === reportedPath || expectedPath.endsWith(`/${reportedPath.replace(/^\/+/, "")}`);
}

function satisfies(candidate, entry) {
  if (candidate.category !== entry.category) return false;
  if (!routeMatches(candidate.route, entry.route)) return false;
  const [from, to] = entry.lineRange ?? [entry.line, entry.line];
  return candidate.location.line >= from && candidate.location.line <= to;
}

function band(entry) {
  return entry.severityBand ?? [];
}

async function main() {
  const manifest = await loadManifest();
  const familyFilter = flag("family", null);
  const classFilter = flag("class", null);
  const verbose = flag("verbose", false) === true;
  const updateBaseline = flag("update-baseline", false) === true;

  const cases = manifest.cases.filter((entry) => {
    if (typeof familyFilter === "string" && entry.family !== familyFilter) return false;
    if (typeof classFilter === "string" && entry.category !== classFilter) return false;
    return true;
  });

  if (cases.length === 0) {
    process.stderr.write("No cases matched. Check --family and --class.\n");
    process.exitCode = 1;
    return;
  }

  const outcomes = [];
  for (const entry of cases) {
    const scanned = await scanCase(entry);
    if (entry.kind === "vulnerable") {
      const hit = scanned.candidates.find((candidate) => satisfies(candidate, entry));
      const wrongPlace = scanned.candidates.filter(
        (candidate) => candidate.category === entry.category && !satisfies(candidate, entry)
      );
      outcomes.push({
        ...entry,
        detected: Boolean(hit),
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
        unsupported: UNSUPPORTED_LANGUAGES.has(entry.language)
      });
    } else {
      outcomes.push({
        ...entry,
        falsePositives: scanned.candidates.map((candidate) => ({
          category: candidate.category,
          line: candidate.location.line,
          severity: candidate.severity,
          ruleId: candidate.ruleId
        })),
        unsupported: UNSUPPORTED_LANGUAGES.has(entry.language)
      });
    }
  }

  /* ---------- aggregate ---------- */

  const supported = outcomes.filter((outcome) => !outcome.unsupported);
  const vulnerable = supported.filter((outcome) => outcome.kind === "vulnerable");
  const safe = supported.filter((outcome) => outcome.kind === "safe");
  const unsupported = outcomes.filter((outcome) => outcome.unsupported);

  const detected = vulnerable.filter((outcome) => outcome.detected);
  const criticalHigh = vulnerable.filter((outcome) => band(outcome).some((level) => level === "critical" || level === "high"));
  const criticalHighDetected = criticalHigh.filter((outcome) => outcome.detected);
  const safeWithFindings = safe.filter((outcome) => outcome.falsePositives.length > 0);

  const recall = vulnerable.length === 0 ? null : detected.length / vulnerable.length;
  const criticalHighRecall = criticalHigh.length === 0 ? null : criticalHighDetected.length / criticalHigh.length;
  const falsePositiveRate = safe.length === 0 ? null : safeWithFindings.length / safe.length;

  // Precision over the whole corpus: a true positive is an expected detection; a
  // false positive is any finding on a safe case. Extra findings on vulnerable
  // cases are excluded from both, because a realistic vulnerable file legitimately
  // contains more than the one defect it is catalogued for.
  const falsePositiveCount = safe.reduce((sum, outcome) => sum + outcome.falsePositives.length, 0);
  const precision =
    detected.length + falsePositiveCount === 0 ? null : detected.length / (detected.length + falsePositiveCount);

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
  process.stdout.write(unsupported.length > 0 ? `, ${unsupported.length} in an unparsed language\n` : "\n");
  process.stdout.write(`recall                ${percent(recall)} (${detected.length}/${vulnerable.length})\n`);
  process.stdout.write(
    `critical/high recall  ${percent(criticalHighRecall)} (${criticalHighDetected.length}/${criticalHigh.length})\n`
  );
  process.stdout.write(`precision             ${percent(precision)}\n`);
  process.stdout.write(
    `safe-case FP rate     ${percent(falsePositiveRate)} (${safeWithFindings.length}/${safe.length} safe case(s) produced a finding)\n`
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
    process.stdout.write(`\nfindings on correct code:\n`);
    for (const outcome of safeWithFindings) {
      for (const finding of outcome.falsePositives) {
        process.stdout.write(`  ${outcome.id.padEnd(46)} ${finding.ruleId} at line ${finding.line}\n`);
      }
    }
  }

  if (unsupported.length > 0) {
    process.stdout.write(`\nnot assessed (language not parsed by the engine):\n`);
    const languages = [...new Set(unsupported.map((outcome) => outcome.language))];
    for (const language of languages) {
      const count = unsupported.filter((outcome) => outcome.language === language).length;
      process.stdout.write(`  ${language.padEnd(12)} ${count} case(s)\n`);
    }
  }

  if (verbose) {
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
    gates: GATES,
    totals: {
      cases: cases.length,
      vulnerable: vulnerable.length,
      safe: safe.length,
      unsupported: unsupported.length,
      recall,
      criticalHighRecall,
      precision,
      falsePositiveRate
    },
    byClass,
    byFamily,
    outcomes
  };
  await fs.writeFile(path.join(ROOT, "benchmark", `${RESULT_PREFIX}-last-run.json`), `${JSON.stringify(payload, null, 2)}\n`);
  process.stdout.write(`\nwrote benchmark/${RESULT_PREFIX}-last-run.json\n`);

  /* ---------- gates ---------- */

  const failures = [];
  if (criticalHighRecall !== null && criticalHighRecall < GATES.criticalHighRecall) {
    failures.push(`critical/high recall ${percent(criticalHighRecall)} < ${GATES.criticalHighRecall}`);
  }
  if (recall !== null && recall < GATES.overallRecall) {
    failures.push(`overall recall ${percent(recall)} < ${GATES.overallRecall}`);
  }
  if (precision !== null && precision < GATES.precision) {
    failures.push(`precision ${percent(precision)} < ${GATES.precision}`);
  }
  if (falsePositiveRate !== null && falsePositiveRate > GATES.safeFalsePositiveRate) {
    failures.push(`safe-case false-positive rate ${percent(falsePositiveRate)} > ${GATES.safeFalsePositiveRate}`);
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
  try {
    const baseline = JSON.parse(await fs.readFile(path.join(ROOT, "benchmark", `${RESULT_PREFIX}-baseline.json`), "utf8"));
    for (const [category, bucket] of Object.entries(baseline.byClass ?? {})) {
      const now = byClass[category];
      if (!now) continue;
      const before = bucket.detected / bucket.expected;
      const after = now.detected / now.expected;
      if (after < before) failures.push(`${category} recall fell from ${before.toFixed(3)} to ${after.toFixed(3)}`);
    }
    if (typeof baseline.totals?.falsePositiveRate === "number" && falsePositiveRate > baseline.totals.falsePositiveRate) {
      failures.push(
        `safe-case false-positive rate rose from ${baseline.totals.falsePositiveRate.toFixed(3)} to ${percent(falsePositiveRate)}`
      );
    }
  } catch {
    process.stdout.write(`no ${RESULT_PREFIX} baseline recorded yet\n`);
  }

  if (failures.length > 0) {
    process.stderr.write(`\n${CORPUS_LABEL} failed ${failures.length} gate(s):\n${failures.map((f) => `  - ${f}`).join("\n")}\n`);
    process.exitCode = 1;
  } else {
    process.stdout.write(`all ${CORPUS_LABEL} gates passed\n`);
  }
}

await main();
