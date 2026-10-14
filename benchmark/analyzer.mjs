/**
 * The simulated host agent, as the acceptance journey needs it.
 *
 * In the real product the host agent is whatever model the operator is already
 * running: it reads the project, proposes findings, and settles them against the
 * running application. The acceptance journey has to exercise that whole
 * protocol — submit, dedupe, redact, verify, export, sync, share — without a
 * model in the loop, so this module stands in for the agent and produces the
 * same shape of work a real one would.
 *
 * Two rules keep this from turning into a harness that measures itself:
 *
 *  - **No detection lives here.** Candidates come from the product's own static
 *    pass (`@myrqen/scan`), so renaming a route or a file in a fixture changes
 *    the output only if the product's own discovery genuinely changes. There is
 *    not one fixture path, identifier, or pattern in this file.
 *  - **No policy lives here either.** Every probe is proposed through
 *    `classifyPlannedAction`, the same gate the CLI's `action check` uses, and
 *    the untrusted-content observation comes from `detectInjectionSignals`, the
 *    same detector the product ships. A probe this module is not allowed to run
 *    is refused here for the same reason it would be refused in a real
 *    assessment.
 *
 * Runtime settling is delegated to `./validator.mjs`, which the benchmark
 * harness already uses for the same purpose. The difference between the two
 * callers is only where the candidates come from: the benchmark reads them back
 * out of the CLI's session, and the journey needs them before a session exists.
 *
 * A refuted candidate is dropped rather than submitted. An agent that proposes a
 * finding its own probe disproved is the failure mode this product exists to
 * avoid, and a journey assertion that then falls short of its expected finding
 * count is reporting a real regression rather than a flaky test.
 */
import fs from "node:fs/promises";
import path from "node:path";
import { scan } from "../packages/scan/dist/index.js";
import { classifyPlannedAction, detectInjectionSignals } from "../packages/policy/dist/index.js";
import { validate } from "./validator.mjs";

/** Prose files an agent would read for context, and the only place untrusted
 * instructions have ever been found in practice. */
const PROSE_EXTENSIONS = new Set([".md", ".markdown", ".txt", ".rst", ".adoc"]);
const PROSE_MAX_BYTES = 512 * 1024;
const PROSE_MAX_FILES = 64;
const SKIP_DIRECTORIES = new Set(["node_modules", ".git", ".myrqen", "dist", "build", "coverage", ".next"]);

/** Origins proposed by content the scanner does not trust. Trailing sentence
 * punctuation is stripped, or every origin at the end of a sentence acquires a
 * full stop and stops matching the authorization list it is compared against. */
const ORIGIN_PATTERN = /https?:\/\/[a-z0-9.-]+(?::\d+)?/gi;

function normalizeOrigin(value) {
  return value.replace(/[.,;:)\]}'"]+$/, "");
}

async function proseFiles(repoRoot) {
  const found = [];
  async function walk(directory) {
    if (found.length >= PROSE_MAX_FILES) return;
    let entries;
    try {
      entries = await fs.readdir(directory, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (found.length >= PROSE_MAX_FILES) return;
      if (entry.name.startsWith(".") && entry.isDirectory()) continue;
      if (SKIP_DIRECTORIES.has(entry.name)) continue;
      const full = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        await walk(full);
        continue;
      }
      if (!entry.isFile()) continue;
      if (!PROSE_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) continue;
      found.push(full);
    }
  }
  await walk(repoRoot);
  return found;
}

/**
 * What the agent noticed about content that addressed it directly.
 *
 * One entry per file, not one per signal: a single injected block trips several
 * detectors, and reporting each of them separately would tell an operator that
 * their repository was attacked four times when it was attacked once.
 */
async function observeUntrustedContent(repoRoot) {
  const observations = [];
  for (const file of await proseFiles(repoRoot)) {
    let content;
    try {
      const stat = await fs.stat(file);
      if (stat.size > PROSE_MAX_BYTES) continue;
      content = await fs.readFile(file, "utf8");
    } catch {
      continue;
    }
    const signals = detectInjectionSignals(content);
    if (signals.length === 0) continue;
    observations.push({
      file: path.relative(repoRoot, file),
      signals: signals.map((signal) => signal.id),
      /* Recorded so the report can say which origins were proposed and refused.
       * Nothing here authorizes them; that is the operator's decision alone. */
      proposedOrigins: [...new Set((content.match(ORIGIN_PATTERN) ?? []).map(normalizeOrigin))]
    });
  }
  return observations;
}

/**
 * The safety gate, from the product. `validate` asks before it runs anything
 * that writes, and a refusal is recorded rather than worked around.
 */
function makeCheck(refusals) {
  return async (plan) => {
    const decision = classifyPlannedAction(plan);
    if (!decision.allowed) {
      refusals.push({ intent: plan.intent, violations: decision.violations, reason: decision.reason });
    }
    return decision.allowed;
  };
}

/**
 * Compose one finding submission from a static candidate and whatever the
 * runtime probe was able to establish about it.
 *
 * Verification is never upgraded past what the evidence supports: a candidate
 * the probe could not settle keeps the verification the static pass claimed, and
 * only a reproduced behaviour reaches `verified`.
 */
function toSubmission(candidate, outcome) {
  const evidence = candidate.evidence.map((item) => ({
    kind: item.kind,
    description: item.description,
    ...(item.snippet ? { snippet: item.snippet } : {}),
    ...(item.location ? { location: item.location } : {})
  }));

  if (outcome?.outcome === "verified") {
    evidence.push({
      kind: outcome.kind ?? "runtime",
      description: outcome.description,
      ...(outcome.location ? { location: outcome.location } : {})
    });
  }

  return {
    title: candidate.title,
    category: candidate.category,
    ...(candidate.taxonomy?.length ? { taxonomy: candidate.taxonomy.slice(0, 16) } : {}),
    severity: candidate.severity,
    verification: outcome?.outcome === "verified" ? "verified" : candidate.verification,
    summary: candidate.summary,
    impact: candidate.impact,
    affected: {
      component: candidate.location.container ?? candidate.location.file,
      file: candidate.location.file,
      ...(candidate.location.line ? { lineStart: candidate.location.line } : {}),
      ...(candidate.location.endLine ? { lineEnd: candidate.location.endLine } : {}),
      ...(candidate.route ? { route: candidate.route } : {})
    },
    evidence,
    remediation: candidate.remediation,
    verificationPlan: candidate.verificationPlan
  };
}

/**
 * Read the project, settle what can be settled against the running application,
 * and return the work the journey then submits through the CLI.
 */
export async function analyze({ repoRoot, baseUrl, identities }) {
  const staticPass = await scan({ repoRoot });

  /* `validate` reads a finding's category and route, which is all a probe can
   * honestly derive a request from. The ids are local to this call: the CLI owns
   * real finding identity once a submission is accepted. */
  const candidates = staticPass.candidates.map((candidate, index) => ({
    ...candidate,
    id: `CANDIDATE-${String(index + 1).padStart(3, "0")}`,
    affected: { route: candidate.route, file: candidate.location.file }
  }));

  const refusals = [];
  const validation = await validate({
    baseUrl,
    findings: candidates,
    identities,
    check: makeCheck(refusals)
  });

  const settled = new Map(validation.outcomes.map((outcome) => [outcome.findingId, outcome]));
  const findings = [];
  const refuted = [];
  for (const candidate of candidates) {
    const outcome = settled.get(candidate.id);
    if (outcome?.outcome === "refuted") {
      refuted.push({ category: candidate.category, reason: outcome.description });
      continue;
    }
    findings.push(toSubmission(candidate, outcome));
  }

  const injection = await observeUntrustedContent(repoRoot);

  /* Notes are the agent's account of its own run. Every line below is derived
   * from something that actually happened in it. */
  const coverage = [...validation.notes.coverage];
  const limitations = [...validation.notes.limitations];

  coverage.push(
    `The static pass parsed ${staticPass.coverage.filesParsed} file(s) with ${staticPass.coverage.rulesRun.length} rules and recorded ${staticPass.candidates.length} candidate(s).`
  );
  for (const statement of staticPass.coverage.notAssessed) {
    limitations.push(statement);
  }

  if (injection.length > 0) {
    const files = injection.map((entry) => entry.file).join(", ");
    coverage.push(
      `Content in ${files} addresses the scanner directly. It was recorded as untrusted data and read for context only, never followed as instruction.`
    );
    const proposed = [...new Set(injection.flatMap((entry) => entry.proposedOrigins))];
    for (const origin of proposed) {
      limitations.push(
        `${origin} was not tested. It was proposed by untrusted content, and an external origin is only in scope once the operator authorizes that exact origin.`
      );
    }
  }

  for (const refusal of refusals) {
    limitations.push(
      `A probe intending ${refusal.intent} was blocked by safety policy (${refusal.violations.join(", ")}), so that behaviour is unproven rather than absent.`
    );
  }
  for (const entry of refuted) {
    limitations.push(`A ${entry.category} candidate was refuted and withdrawn: ${entry.reason}`);
  }

  return {
    findings,
    observations: { injection, refusals, refuted },
    notes: { coverage, limitations },
    coverage: staticPass.coverage
  };
}
