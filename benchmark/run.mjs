#!/usr/bin/env node
/**
 * Benchmark harness.
 *
 * Starts each fixture, drives the real Myrqen CLI through the full scan protocol,
 * lets the CLI's own static pass find what it can, has a simulated host agent
 * settle every candidate against the running application, then scores the result
 * against machine-readable ground truth.
 *
 * Two properties matter more than any score here:
 *
 *  - The detection being measured is the product's. The harness contains no rules
 *    and no fixture-specific patterns, so renaming a route in a fixture changes
 *    the score only if the product's route discovery genuinely fails.
 *  - Matching is strict. A finding counts for a ground-truth case only when the
 *    category matches, the route matches when one is specified, and the evidence
 *    meets the case's minimum. Loose matching flatters recall and hides exactly
 *    the misattribution a reader would notice first.
 *
 * Metrics that must be zero: safety policy violations and canary leakage.
 * Release gates are enforced here and fail the process, so a regression cannot
 * be reported as a pass.
 */
import { spawn } from "node:child_process";
import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { discover, validate } from "./validator.mjs";
import { UNSAFE_PROBES } from "./unsafe-probes.mjs";

const run = promisify(execFile);

/**
 * A throwaway config directory for the whole benchmark.
 *
 * Without this the benchmark reads and writes the *operator's* real Myrqen config — the CLI
 * defaults `MYRQEN_CONFIG_DIR` to the user's config root, and every `cli()` call here
 * inherited it. So a benchmark run mutated the state of the installed product on the machine
 * running it, and a stale entry from a previous run could change what the next run measured.
 *
 * Created once per process rather than per fixture, because the session state the CLI keeps
 * between `scan` and `finding submit` has to survive across calls within one fixture.
 */
const CONFIG_DIR = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-benchmark-cfg-"));
const ROOT = path.resolve(import.meta.dirname, "..");
const CLI = path.join(ROOT, "apps", "cli", "dist", "myrqen.mjs");

const argv = process.argv.slice(2);
/*
 * Removes the agent's discovery stage, leaving only the settling of static candidates.
 * It exists so `tests/harness-e2e.test.mjs` can prove the static and whole-product
 * figures move independently — if they do not, the harness is measuring the static
 * pass twice and calling one of them the product.
 */
const SKIP_DISCOVERY = argv.includes("--no-discovery");
function flag(name, fallback) {
  const index = argv.indexOf(`--${name}`);
  if (index === -1) return fallback;
  const value = argv[index + 1];
  return value && !value.startsWith("--") ? value : true;
}

const FIXTURES = [
  { id: "vuln-shop", port: 4010 },
  { id: "safe-app", port: 4020 },
  /*
   * Python fixtures (ADR 020). They need a Python interpreter with the packages in
   * each fixture's requirements.txt; Myrqen itself does not. Where those are
   * missing the fixture is skipped and the run says so — a skipped fixture is
   * not compared with the baseline, so it can neither pass nor fail a gate.
   */
  {
    id: "vuln-fastapi",
    port: 5030,
    python: { args: ["-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "{port}"], imports: ["fastapi", "uvicorn", "jinja2"] }
  },
  { id: "vuln-flask", port: 5040, python: { args: ["run.py"], imports: ["flask"] } }
];

const PYTHON = process.env.MYRQEN_BENCHMARK_PYTHON ?? "python3";

/** Why a Python fixture cannot run here, or null when it can. */
async function pythonUnavailable(fixture) {
  if (!fixture.python) return null;
  try {
    await run(PYTHON, ["-c", `import ${fixture.python.imports.join(", ")}`], { timeout: 20_000 });
    return null;
  } catch {
    return `${PYTHON} cannot import ${fixture.python.imports.join(", ")} (pip install -r fixtures/${fixture.id}/requirements.txt)`;
  }
}

/**
 * Release gates, from docs/12-release. These are computed from real ground truth
 * and enforced: falling below any of them exits non-zero.
 */
const GATES = {
  criticalHighRecall: 0.95,
  overallRecall: 0.9,
  precision: 0.9,
  safeAppFalsePositiveRate: 0.03,
  canaryLeaks: 0,
  unauthorizedTargets: 0,
  destructiveEscapes: 0
};

async function waitForHealth(baseUrl, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${baseUrl}/health`);
      if (response.ok) return true;
    } catch {
      // not up yet
    }
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  return false;
}

function startFixture(fixtureRoot, port, fixture = {}) {
  const [command, args] = fixture.python
    ? [PYTHON, fixture.python.args.map((arg) => arg.replace("{port}", String(port)))]
    : [process.execPath, [path.join(fixtureRoot, "src", "server.js")]];
  const child = spawn(command, args, {
    cwd: fixtureRoot,
    env: { ...process.env, PORT: String(port), PYTHONDONTWRITEBYTECODE: "1" },
    stdio: ["ignore", "pipe", "pipe"]
  });
  child.stdout.on("data", () => undefined);
  child.stderr.on("data", () => undefined);
  return child;
}

async function cli(args, options = {}) {
  const { stdout } = await run(process.execPath, [CLI, ...args], {
    cwd: options.cwd ?? ROOT,
    env: {
      ...process.env,
      MYRQEN_CONFIG_DIR: CONFIG_DIR,
      MYRQEN_NON_INTERACTIVE: "1",
      MYRQEN_NO_COLOR: "1",
      ...(options.env ?? {})
    },
    /*
     * No stdin plumbing here on purpose. Async `execFile` has no `input` option — that
     * is `execFileSync` — so passing one silently does nothing and leaves the child
     * waiting on a stdin that never closes. Anything needing stdin uses `cliSubmit`.
     */
    maxBuffer: 32 * 1024 * 1024
  });
  return stdout;
}

async function cliJson(args, options = {}) {
  const stdout = await cli(["--json", ...args], options);
  const start = stdout.indexOf("{");
  if (start === -1) throw new Error(`Expected JSON from "${args.join(" ")}" but received:\n${stdout}`);
  return JSON.parse(stdout.slice(start));
}

/** A non-zero exit is a legitimate outcome for a gate; read the JSON regardless. */
async function cliJsonTolerant(args, options = {}, fallback = {}) {
  try {
    return await cliJson(args, options);
  } catch (error) {
    const text = String(error.stdout ?? "");
    const start = text.indexOf("{");
    return start === -1 ? fallback : JSON.parse(text.slice(start));
  }
}

function severityBandMatches(actual, band) {
  return band.includes(actual);
}

/**
 * Does this finding satisfy the ground-truth case?
 *
 * Every stated attribute must match. Where the case names a route, a finding on
 * the right category in the wrong place does not count — misattribution is a
 * defect a reader hits immediately, and scoring it as a hit hides it.
 */
function matches(finding, expected) {
  if (finding.category !== expected.category) return false;
  if (expected.route && finding.affected.route !== expected.route) return false;
  if (expected.file && finding.affected.file !== expected.file) return false;
  if (expected.lineRange) {
    const [from, to] = expected.lineRange;
    const line = finding.affected.lineStart;
    if (typeof line !== "number" || line < from || line > to) return false;
  }
  return true;
}

/** Does the finding carry the evidence the case demands? */
function evidenceShortfall(finding, expected) {
  const minimum = expected.minimumEvidence;
  if (!minimum) return null;
  const pool = [...(finding.evidence ?? []), ...(finding.corroboration ?? [])];
  if (minimum.count && pool.length < minimum.count) {
    return `expected at least ${minimum.count} evidence item(s), found ${pool.length}`;
  }
  for (const kind of minimum.kinds ?? []) {
    if (!pool.some((item) => item.kind === kind)) return `missing evidence of kind "${kind}"`;
  }
  if (minimum.route && finding.affected.route !== minimum.route) {
    return `expected route ${minimum.route}, found ${finding.affected.route ?? "none"}`;
  }
  return null;
}

async function scoreFixture(fixture) {
  const fixtureRoot = path.join(ROOT, "fixtures", fixture.id);
  const groundTruth = JSON.parse(await fs.readFile(path.join(fixtureRoot, "ground-truth.json"), "utf8"));
  const baseUrl = `http://127.0.0.1:${fixture.port}`;

  const server = startFixture(fixtureRoot, fixture.port, fixture);
  const healthy = await waitForHealth(baseUrl);
  if (!healthy) {
    server.kill("SIGTERM");
    throw new Error(`${fixture.id} did not become healthy on ${baseUrl}`);
  }

  const started = Date.now();
  const safetyViolations = [];
  let unsafeBlocked = 0;
  let unsafeAllowed = 0;

  try {
    // Clean any previous local state so runs are comparable.
    await fs.rm(path.join(fixtureRoot, ".myrqen"), { recursive: true, force: true });

    const context = await cliJson(
      [
        "session",
        "start",
        "--effort",
        "auto",
        "--sync",
        "no",
        "--agent",
        "benchmark-harness",
        "--model",
        "candidate-driven-validator"
      ],
      { cwd: fixtureRoot }
    );

    for (const phase of ["scope", "discovery", "source_review"]) {
      await cli(["phase", "start", phase], { cwd: fixtureRoot });
    }

    // Prove the safety gate refuses destructive plans.
    for (const probe of UNSAFE_PROBES) {
      const args = ["action", "check", "--intent", probe.intent];
      if (probe.description) args.push("--description", probe.description);
      if (probe.method) args.push("--method", probe.method);
      if (probe.repeatCount) args.push("--repeat", String(probe.repeatCount));
      const decision = await cliJsonTolerant(args, { cwd: fixtureRoot }, { allowed: true });
      if (decision.allowed) {
        unsafeAllowed += 1;
        safetyViolations.push(`safety gate allowed ${probe.intent}`);
      } else {
        unsafeBlocked += 1;
      }
    }

    // Prove injected origins are never authorized without confirmation.
    for (const origin of groundTruth.promptInjection?.mustNotAuthorize ?? []) {
      const decision = await cliJsonTolerant(["target", "authorize", origin], { cwd: fixtureRoot }, { decision: "denied" });
      if (decision.decision === "authorized" || decision.decision === "already_authorized") {
        safetyViolations.push(`injected origin ${origin} was authorized`);
      }
    }

    /* ---------- the agent's part: settle every static candidate ---------- */

    for (const phase of ["runtime_validation", "access_control"]) {
      await cli(["phase", "start", phase], { cwd: fixtureRoot });
    }

    // One gate for both stages: a discovery probe is checked exactly as a settling
    // probe is, so nothing reaches the application that the policy would refuse.
    const actionCheck = async (plan) => {
      const decision = await cliJsonTolerant(
        [
          "action",
          "check",
          "--intent",
          plan.intent,
          ...(plan.description ? ["--description", plan.description] : []),
          ...(plan.method ? ["--method", plan.method] : []),
          ...(plan.target ? ["--target", plan.target] : [])
        ],
        { cwd: fixtureRoot },
        { allowed: false }
      );
      return Boolean(decision.allowed);
    };

    const beforeValidation = await readSession(fixtureRoot);
    const validation = await validate({
      baseUrl,
      findings: beforeValidation.findings,
      identities: groundTruth.identities,
      check: actionCheck
    });

    for (const outcome of validation.outcomes) {
      if (outcome.outcome === "verified") {
        await cli(
          [
            "finding",
            "verify",
            outcome.findingId,
            "--kind",
            outcome.kind ?? "runtime",
            "--description",
            outcome.description,
            ...(outcome.location ? ["--location", outcome.location] : [])
          ],
          { cwd: fixtureRoot }
        );
      } else if (outcome.outcome === "refuted") {
        await cli(["finding", "refute", outcome.findingId, "--reason", outcome.description], { cwd: fixtureRoot });
      }
    }

    for (const note of validation.notes.coverage) await cli(["note", "coverage", note], { cwd: fixtureRoot });
    for (const note of validation.notes.limitations) await cli(["note", "limitation", note], { cwd: fixtureRoot });

    // Exercise dedupe with a genuine second reading of the first finding.
    let duplicateOutcome = "not_exercised";
    if (beforeValidation.findings.length > 0) {
      const first = beforeValidation.findings[0];
      const duplicate = {
        title: first.title,
        category: first.category,
        severity: first.severity,
        verification: "needs_review",
        summary: first.summary,
        impact: first.impact,
        affected: first.affected,
        evidence: [
          {
            kind: "source",
            description:
              "A second review pass reached the same root cause from the source path rather than from the runtime probe."
          }
        ],
        remediation: first.remediation,
        verificationPlan: first.verificationPlan
      };
      const result = await cliSubmit(duplicate, fixtureRoot);
      duplicateOutcome = result.action ?? "rejected";
    }

    await cli(["metrics", "token", "--source", "unavailable"], { cwd: fixtureRoot });
    for (const phase of ["scope", "discovery", "source_review", "runtime_validation", "access_control", "validation"]) {
      await cli(["phase", "complete", phase], { cwd: fixtureRoot });
    }

    /* ---------- the agent's other part: find what the static pass did not ---------- */

    /*
     * This is the half the harness could not measure. Until the fixture carried
     * defects the static pass cannot see, `validate` only ever settled candidates the
     * static pass had already produced — so recall shared its numerator and its
     * denominator with `staticPass.candidatesRecorded` and could not move.
     *
     * Skippable, because the harness test needs a run with the agent's contribution
     * removed in order to prove that these two numbers are independent.
     */
    const discovery = SKIP_DISCOVERY
      ? { found: [], failures: ["discovery skipped by --no-discovery"], identitiesUsed: [] }
      : await discover({ baseUrl, identities: groundTruth.identities, check: actionCheck });

    for (const found of discovery.found) {
      const submission = {
        title: found.title,
        category: found.category,
        severity: found.severity,
        verification: "verified",
        summary: found.summary,
        impact: found.summary,
        remediation: found.remediation,
        verificationPlan: found.verificationPlan,
        affected: { component: found.route ?? found.file, file: found.file, route: found.route },
        evidence: [{ kind: found.kind, description: found.evidence }],
        reproduction: found.evidence
      };
      // `cliSubmit` rather than `cli`: async `execFile` has no `input` option, so a
      // submission piped that way leaves the child waiting on stdin for ever.
      // A refusal from intake is information, not a crash.
      try {
        // `cliSubmit` resolves on close whatever the exit code, so a refusal looks
        // like a success unless `accepted` is read. Recording the reason is the whole
        // value of this stage: a discovery the intake rejects is a harness defect, not
        // a detection result.
        const outcome = await cliSubmit(submission, fixtureRoot);
        if (outcome?.accepted === false) {
          discovery.failures.push(
            `intake refused ${found.category}: ${(outcome.problems ?? outcome.errors ?? [outcome.reason ?? "no reason given"]).join?.("; ") ?? JSON.stringify(outcome)}`
          );
        }
      } catch (error) {
        discovery.failures.push(`submitting ${found.category}: ${error instanceof Error ? error.message : "unknown"}`);
      }
    }

    const finish = await cliJson(["session", "finish"], { cwd: fixtureRoot });
    const report = JSON.parse(await fs.readFile(finish.files.json, "utf8"));
    const html = await fs.readFile(finish.files.html, "utf8");
    const durationMs = Date.now() - started;

    /* ---------- scoring ---------- */

    // A refuted finding is the agent stating it could not reproduce the candidate.
    // Scoring it as a report would punish honesty; scoring it as absent would
    // reward deleting inconvenient findings. It is counted separately.
    const reported = report.findings.filter((finding) => finding.status !== "false_positive");
    const refuted = report.findings.filter((finding) => finding.status === "false_positive");

    /*
     * A case is `staticVisible` when the static pass could reach it at all. Three of
     * this fixture's cases are not: one crosses a module boundary, one is a pair of
     * responses no rule models, and one is an operation that reads correctly and is
     * only wrong when repeated. They exist so the whole-product figure can lose.
     */
    const staticVisible = groundTruth.expected.filter((entry) => entry.staticVisible !== false);
    const agentOnly = groundTruth.expected.filter((entry) => entry.staticVisible === false);

    const matched = new Map();
    const unmatched = [];
    for (const finding of reported) {
      const expected = groundTruth.expected.find((candidate) => matches(finding, candidate));
      if (expected) {
        matched.set(expected.id, [...(matched.get(expected.id) ?? []), finding]);
      } else {
        unmatched.push({
          id: finding.id,
          category: finding.category,
          severity: finding.severity,
          verification: finding.verification,
          location: `${finding.affected.file ?? "?"}:${finding.affected.lineStart ?? "?"}`,
          route: finding.affected.route ?? null
        });
      }
    }

    const missed = groundTruth.expected.filter((expected) => !matched.has(expected.id));
    const severityMismatches = [];
    const verificationMismatches = [];
    const evidenceShortfalls = [];
    for (const expected of groundTruth.expected) {
      const found = matched.get(expected.id)?.[0];
      if (!found) continue;
      if (!severityBandMatches(found.severity, expected.severityBand)) {
        severityMismatches.push({ expected: expected.id, band: expected.severityBand, actual: found.severity });
      }
      if (expected.verification === "verified" && found.verification !== "verified") {
        verificationMismatches.push({ expected: expected.id, actual: found.verification });
      }
      const shortfall = evidenceShortfall(found, expected);
      if (shortfall) evidenceShortfalls.push({ expected: expected.id, shortfall });
    }

    const serialized = `${JSON.stringify(report)}\n${html}`;
    const leakedCanaries = (groundTruth.canarySecrets ?? []).filter((secret) => serialized.includes(secret));
    if (leakedCanaries.length > 0) safetyViolations.push(`${leakedCanaries.length} canary secret(s) present in report output`);

    const expectedCount = groundTruth.expected.length;
    const truePositives = matched.size;
    const falsePositives = unmatched.length;

    /* ---------- per-category and per-severity detail ---------- */

    const byCategory = {};
    for (const expected of groundTruth.expected) {
      const bucket = (byCategory[expected.category] ??= { expected: 0, found: 0 });
      bucket.expected += 1;
      if (matched.has(expected.id)) bucket.found += 1;
    }
    for (const [category, bucket] of Object.entries(byCategory)) {
      bucket.recall = Number((bucket.found / bucket.expected).toFixed(3));
    }

    const criticalHigh = groundTruth.expected.filter((expected) =>
      expected.severityBand.some((band) => band === "critical" || band === "high")
    );
    const criticalHighFound = criticalHigh.filter((expected) => matched.has(expected.id)).length;

    return {
      fixture: fixture.id,
      durationMs,
      contextEffort: { requested: context.effort.requested, resolved: context.effort.resolved },
      staticPass: context.staticPass ?? null,
      expected: expectedCount,
      reported: reported.length,
      refuted: refuted.length,
      truePositives,
      falsePositives,
      unmatched,
      missed: missed.map((entry) => entry.id),
      recall: expectedCount === 0 ? null : Number((truePositives / expectedCount).toFixed(3)),
      /*
       * The two halves of the product, reported separately, because a single figure
       * cannot say which of them found anything.
       *
       * `staticRecall` counts ground-truth cases the static pass could see at all —
       * the cases marked `staticVisible`. `endToEndRecall` counts what the finished
       * report contains, over every case including the ones no static rule can reach.
       * A gap between them is the agent's contribution; no gap means the harness is
       * measuring the static pass twice and calling one of them the product.
       */
      staticVisibleExpected: staticVisible.length,
      staticRecall:
        staticVisible.length === 0
          ? null
          : Number((staticVisible.filter((entry) => matched.has(entry.id)).length / staticVisible.length).toFixed(3)),
      agentOnlyExpected: agentOnly.length,
      agentOnlyRecall:
        agentOnly.length === 0
          ? null
          : Number((agentOnly.filter((entry) => matched.has(entry.id)).length / agentOnly.length).toFixed(3)),
      endToEndRecall: expectedCount === 0 ? null : Number((truePositives / expectedCount).toFixed(3)),
      discovery: {
        found: discovery.found.length,
        failures: discovery.failures,
        categories: discovery.found.map((entry) => entry.category)
      },
      criticalHighRecall:
        criticalHigh.length === 0 ? null : Number((criticalHighFound / criticalHigh.length).toFixed(3)),
      precision: reported.length === 0 ? null : Number((truePositives / reported.length).toFixed(3)),
      byCategory,
      duplicatesPerGroundTruthIssue: [...matched.values()].reduce((sum, list) => sum + Math.max(0, list.length - 1), 0),
      duplicateOutcome,
      verifiedCount: report.summary.verificationCounts.verified,
      validation: {
        verified: validation.outcomes.filter((outcome) => outcome.outcome === "verified").length,
        refuted: validation.outcomes.filter((outcome) => outcome.outcome === "refuted").length,
        unsettled: validation.outcomes.filter((outcome) => outcome.outcome === "unsettled").length,
        identitiesUsed: validation.identitiesUsed,
        outcomes: validation.outcomes
      },
      severityMismatches,
      verificationMismatches,
      evidenceShortfalls,
      safetyViolations,
      unsafeActionsBlocked: unsafeBlocked,
      unsafeActionsAllowed: unsafeAllowed,
      canaryLeaks: leakedCanaries.length,
      reportFiles: finish.files,
      cloudState: finish.cloud.state
    };
  } finally {
    server.kill("SIGTERM");
  }
}

async function readSession(fixtureRoot) {
  const directory = path.join(fixtureRoot, ".myrqen", "sessions");
  const [id] = await fs.readdir(directory);
  return JSON.parse(await fs.readFile(path.join(directory, id, "session.json"), "utf8"));
}

async function cliSubmit(finding, cwd) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, "--json", "finding", "submit"], {
      cwd,
      env: {
        ...process.env,
        MYRQEN_CONFIG_DIR: CONFIG_DIR,
        MYRQEN_NON_INTERACTIVE: "1",
        MYRQEN_NO_COLOR: "1"
      },
      stdio: ["pipe", "pipe", "pipe"]
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.stderr.on("data", (chunk) => (stderr += chunk));
    child.on("error", reject);
    child.on("close", () => {
      const start = stdout.indexOf("{");
      if (start === -1) {
        reject(new Error(`finding submit produced no JSON. stderr: ${stderr}`));
        return;
      }
      resolve(JSON.parse(stdout.slice(start)));
    });
    child.stdin.end(JSON.stringify(finding));
  });
}

/**
 * Which gates this run fails. A vulnerable fixture is judged on recall and
 * precision; a safe fixture is judged on its false-positive rate, because it has
 * no ground truth to recall.
 */
function gateFailures(results) {
  const failures = [];
  for (const result of results) {
    const isSafe = result.expected === 0;
    if (isSafe) {
      const rate = result.reported / Math.max(1, result.staticPass?.filesParsed ?? 1);
      if (result.reported > 0 && rate > GATES.safeAppFalsePositiveRate) {
        failures.push(
          `${result.fixture}: ${result.reported} finding(s) on an application with no ground-truth issues (rate ${rate.toFixed(3)} > ${GATES.safeAppFalsePositiveRate})`
        );
      }
      continue;
    }
    if (result.criticalHighRecall !== null && result.criticalHighRecall < GATES.criticalHighRecall) {
      failures.push(
        `${result.fixture}: critical/high recall ${result.criticalHighRecall} < ${GATES.criticalHighRecall}`
      );
    }
    if (result.recall !== null && result.recall < GATES.overallRecall) {
      failures.push(`${result.fixture}: overall recall ${result.recall} < ${GATES.overallRecall}`);
    }
    if (result.precision !== null && result.precision < GATES.precision) {
      failures.push(`${result.fixture}: precision ${result.precision} < ${GATES.precision}`);
    }
  }

  const leaks = results.reduce((sum, result) => sum + result.canaryLeaks, 0);
  if (leaks > GATES.canaryLeaks) failures.push(`${leaks} canary secret(s) leaked into report output`);

  const violations = results.flatMap((result) => result.safetyViolations);
  if (violations.length > GATES.destructiveEscapes) failures.push(...violations);

  return failures;
}

/** Regressions against the committed baseline, which is a separate failure mode. */
async function regressions(results) {
  const baselinePath = path.join(ROOT, "benchmark", "baseline.json");
  let baseline;
  try {
    baseline = JSON.parse(await fs.readFile(baselinePath, "utf8"));
  } catch {
    return { checked: false, failures: [] };
  }

  const failures = [];
  for (const result of results) {
    const previous = baseline.results?.find((entry) => entry.fixture === result.fixture);
    if (!previous) continue;
    for (const metric of ["recall", "criticalHighRecall", "precision"]) {
      const before = previous[metric];
      const after = result[metric];
      if (typeof before !== "number" || typeof after !== "number") continue;
      // A small tolerance absorbs nothing: these are exact ratios over a fixed
      // corpus, so any drop is a real change in behaviour.
      if (after < before) failures.push(`${result.fixture}: ${metric} fell from ${before} to ${after}`);
    }
    if (typeof previous.falsePositives === "number" && result.falsePositives > previous.falsePositives) {
      failures.push(
        `${result.fixture}: false positives rose from ${previous.falsePositives} to ${result.falsePositives}`
      );
    }
    for (const missedId of result.missed) {
      if (!previous.missed?.includes(missedId)) failures.push(`${result.fixture}: ${missedId} is newly missed`);
    }
  }
  return { checked: true, failures };
}

async function main() {
  const only = flag("fixture", null);
  const selected = typeof only === "string" ? FIXTURES.filter((fixture) => fixture.id === only) : FIXTURES;
  const updateBaseline = flag("update-baseline", false) === true;
  const results = [];

  for (const fixture of selected) {
    process.stdout.write(`\n=== ${fixture.id} ===\n`);
    const unavailable = await pythonUnavailable(fixture);
    if (unavailable) {
      process.stdout.write(`skipped           ${unavailable}\n`);
      continue;
    }
    const result = await scoreFixture(fixture);
    results.push(result);
    process.stdout.write(`recall            ${result.recall ?? "n/a"} (critical/high ${result.criticalHighRecall ?? "n/a"})\n`);
    process.stdout.write(`precision         ${result.precision ?? "n/a"}\n`);
    process.stdout.write(`reported          ${result.reported} findings (${result.verifiedCount} verified, ${result.refuted} refuted)\n`);
    process.stdout.write(`static pass       ${result.staticPass?.candidatesRecorded ?? "n/a"} candidate(s) from ${result.staticPass?.filesParsed ?? "?"} file(s)\n`);
    process.stdout.write(`validation        ${result.validation.verified} verified, ${result.validation.refuted} refuted, ${result.validation.unsettled} unsettled\n`);
    process.stdout.write(`false positives   ${result.falsePositives}\n`);
    process.stdout.write(`missed            ${result.missed.join(", ") || "none"}\n`);
    process.stdout.write(`duplicates/issue  ${result.duplicatesPerGroundTruthIssue} (dedupe: ${result.duplicateOutcome})\n`);
    process.stdout.write(`unsafe blocked    ${result.unsafeActionsBlocked} (allowed ${result.unsafeActionsAllowed})\n`);
    process.stdout.write(`canary leaks      ${result.canaryLeaks}\n`);
    process.stdout.write(`effort            ${result.contextEffort.requested} -> ${result.contextEffort.resolved}\n`);
    process.stdout.write(`duration          ${Math.round(result.durationMs / 100) / 10}s\n`);

    const weakCategories = Object.entries(result.byCategory).filter(([, bucket]) => bucket.recall < 1);
    if (weakCategories.length > 0) {
      process.stdout.write(
        `per-category misses: ${weakCategories.map(([category, bucket]) => `${category} ${bucket.found}/${bucket.expected}`).join(", ")}\n`
      );
    }
    if (result.unmatched.length > 0) {
      process.stdout.write(
        `unmatched findings (review before treating as false positives):\n${result.unmatched
          .map((entry) => `  ${entry.severity} ${entry.category} ${entry.location} ${entry.route ?? ""}`)
          .join("\n")}\n`
      );
    }
    if (result.severityMismatches.length > 0) {
      process.stdout.write(`severity band mismatches: ${JSON.stringify(result.severityMismatches)}\n`);
    }
    if (result.evidenceShortfalls.length > 0) {
      process.stdout.write(`evidence shortfalls: ${JSON.stringify(result.evidenceShortfalls)}\n`);
    }
    if (result.safetyViolations.length > 0) {
      process.stdout.write(`SAFETY VIOLATIONS: ${result.safetyViolations.join("; ")}\n`);
    }
  }

  const payload = { generatedAt: new Date().toISOString(), gates: GATES, results };
  await fs.writeFile(path.join(ROOT, "benchmark", "last-run.json"), `${JSON.stringify(payload, null, 2)}\n`);
  process.stdout.write(`\nwrote benchmark/last-run.json\n`);

  const failures = gateFailures(results);
  const regression = await regressions(results);

  if (updateBaseline) {
    if (failures.length > 0) {
      process.stderr.write("\nRefusing to update the baseline while gates are failing.\n");
      process.exitCode = 1;
      return;
    }
    await fs.writeFile(path.join(ROOT, "benchmark", "baseline.json"), `${JSON.stringify(payload, null, 2)}\n`);
    process.stdout.write("wrote benchmark/baseline.json\n");
    return;
  }

  if (failures.length > 0) {
    process.stderr.write(`\nBenchmark failed ${failures.length} release gate(s):\n${failures.map((entry) => `  - ${entry}`).join("\n")}\n`);
    process.exitCode = 1;
  }
  if (regression.failures.length > 0) {
    process.stderr.write(
      `\nBenchmark regressed against benchmark/baseline.json:\n${regression.failures.map((entry) => `  - ${entry}`).join("\n")}\n`
    );
    process.exitCode = 1;
  }
  if (failures.length === 0 && regression.failures.length === 0) {
    process.stdout.write(`all gates passed${regression.checked ? " with no regression against the baseline" : " (no baseline recorded yet)"}\n`);
  }
}

await main();
