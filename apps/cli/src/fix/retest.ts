import type { Finding } from "@myrqen/contracts";
import { computeFingerprint, redactDeep } from "@myrqen/policy";
import { RULE_IDS, scan, type Candidate } from "@myrqen/scan";
import { toSubmission } from "../scan/static-pass.js";
import { loadKnownSecrets, type SessionState } from "../session/state.js";
import type { RetestRecord } from "./record.js";

/**
 * Retest one finding, and only that finding.
 *
 * Two kinds of proof exist and a finding may need both:
 *
 * - **Static.** A finding the static pass raised is re-checked by running only
 *   its rule over the repository and asking whether the rule still reports this
 *   location. This is the CLI's own work, deterministic and repeatable.
 * - **Runtime.** A finding that was proved against the running app (verified),
 *   or that the agent found itself, cannot be closed by the static engine going
 *   quiet. Myrqen has no model and sends no requests on its own, so the agent
 *   repeats the original request and reports what came back with `--evidence`.
 *   Without that, the result is `needs_runtime_evidence`, never `pass`.
 */

export interface RetestInput {
  /** What the agent observed when it repeated the request after the fix. */
  evidence?: string;
  /** The agent observed the issue still reproducing. */
  stillReproduces?: boolean;
}

export const STATIC_TAG = "static-pass";

export function staticRuleOf(finding: Finding): string | null {
  const tags = finding.tags ?? [];
  if (!tags.includes(STATIC_TAG)) return null;
  return tags.find((tag) => tag !== STATIC_TAG) ?? null;
}

export function needsRuntimeEvidence(finding: Finding): boolean {
  return finding.verification === "verified" || staticRuleOf(finding) === null;
}

function normalizePath(value: string | undefined): string {
  return (value ?? "").replace(/\\/g, "/").replace(/^\.\//, "");
}

function matches(finding: Finding, candidate: Candidate, ruleId: string): boolean {
  if (ruleId === "dependency-advisory") return true;
  const submission = toSubmission(candidate) as Parameters<typeof computeFingerprint>[0];
  if (finding.fingerprint && computeFingerprint(submission) === finding.fingerprint) return true;
  if (normalizePath(candidate.location.file) !== normalizePath(finding.affected.file)) return false;
  if (finding.affected.route && candidate.route) return finding.affected.route === candidate.route;
  return (candidate.location.container ?? candidate.location.file) === finding.affected.component;
}

export async function runStaticRetest(
  repoRoot: string,
  finding: Finding
): Promise<{ ruleId: string; reproduced: boolean; matches: number } | null> {
  const ruleId = staticRuleOf(finding);
  if (!ruleId) return null;
  const disabledRules = [...RULE_IDS.filter((id) => id !== ruleId), ...(ruleId === "dependency-advisory" ? [] : ["dependency-advisory"])];
  const result = await scan({ repoRoot, disabledRules });
  const hits = result.candidates.filter((candidate) => candidate.ruleId === ruleId && matches(finding, candidate, ruleId));
  return { ruleId, reproduced: hits.length > 0, matches: hits.length };
}

export async function retestFinding(state: SessionState, finding: Finding, input: RetestInput = {}): Promise<RetestRecord> {
  const at = new Date().toISOString();
  const staticResult = await runStaticRetest(state.repoRoot, finding);
  const runtimeNeeded = needsRuntimeEvidence(finding);

  let runtime: RetestRecord["runtime"];
  if (input.evidence?.trim()) {
    // Evidence is the agent's prose about a request and a response; it is
    // redacted against the project's own secrets before it is stored anywhere.
    const knownSecrets = await loadKnownSecrets(state);
    const redacted = redactDeep(input.evidence.trim().slice(0, 2000), knownSecrets).value;
    runtime = { reproduced: Boolean(input.stillReproduces), evidence: redacted };
  } else if (input.stillReproduces) {
    throw new Error("Say what you observed: --still-reproduces needs --evidence describing the request and the response.");
  }

  const lines: string[] = [];
  if (staticResult) {
    lines.push(
      staticResult.reproduced
        ? `static: rule ${staticResult.ruleId} still reports this location`
        : `static: rule ${staticResult.ruleId} no longer reports this location`
    );
  }
  if (runtime) lines.push(`runtime: ${runtime.reproduced ? "still reproduces" : "no longer reproduces"} — ${runtime.evidence}`);

  let outcome: RetestRecord["outcome"];
  if (staticResult?.reproduced || runtime?.reproduced) outcome = "fail";
  else if (runtimeNeeded && !runtime) outcome = "needs_runtime_evidence";
  else outcome = "pass";

  if (outcome === "needs_runtime_evidence") {
    lines.push("runtime: not re-checked yet; this finding needs the agent to repeat the original request");
  }

  return {
    at,
    outcome,
    ...(staticResult ? { static: staticResult } : {}),
    ...(runtime ? { runtime } : {}),
    summary: lines.join("\n")
  };
}
