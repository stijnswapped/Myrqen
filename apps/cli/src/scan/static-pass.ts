import { scan, coverageStatements, type Candidate, type ScanResult } from "@myrqen/scan";
import { submitFinding } from "../agent/protocol.js";
import { markPhase, saveSession, type SessionState } from "../session/state.js";
import { style, write } from "../ui/output.js";

export interface StaticPassResult {
  candidates: number;
  created: number;
  merged: number;
  rejected: number;
  /** Why the intake refused a candidate. Never empty when `rejected` is not 0. */
  rejections: Array<{ ruleId: string; errors: string[] }>;
  coverage: ScanResult["coverage"];
}

/**
 * The static pass the CLI runs itself.
 *
 * Myrqen is agent-native, but a tool whose only detection lives in the agent's
 * head cannot be measured, cannot regress-test, and gives a first-time user
 * nothing if their agent has a bad day. This pass produces candidates from the
 * syntax tree and submits every one of them through the same intake the agent
 * uses, so redaction, fingerprinting, dedupe, and severity normalization behave
 * identically no matter who found the issue.
 *
 * It deliberately does not mark anything `verified`. A static reading cannot
 * observe a response; only the runtime validation phase can, and claiming
 * otherwise would be the single most damaging lie this product could tell.
 */
export async function runStaticPass(
  state: SessionState,
  options: { asJson?: boolean; quiet?: boolean } = {}
): Promise<StaticPassResult> {
  markPhase(state, "source_review", "running");

  const result = await scan({ repoRoot: state.repoRoot });

  let created = 0;
  let merged = 0;
  let rejected = 0;
  const rejections: StaticPassResult["rejections"] = [];

  for (const candidate of result.candidates) {
    const submission = await submitFinding(state, toSubmission(candidate), { asJson: false, quiet: true });
    if (!submission.accepted) {
      rejected += 1;
      rejections.push({ ruleId: candidate.ruleId, errors: submission.errors });
    } else if (submission.action === "merged_as_corroboration") {
      merged += 1;
    } else {
      created += 1;
    }
  }

  // Coverage is recorded whether or not anything was found. A scan that reports
  // nothing has still told the reader what it looked at, and what it could not.
  markPhase(state, "source_review", "complete");
  state.coverage = [...new Set([...state.coverage, ...coverageStatements(result)])];
  state.limitations = [...new Set([...state.limitations, ...result.coverage.notAssessed])];
  await saveSession(state);

  if (!options.asJson && !options.quiet) {
    write(
      `${style.ok("Static pass")} ${result.coverage.filesParsed} file(s), ${result.coverage.rulesRun.length} rules, ${result.coverage.durationMs}ms`
    );
    write(`${created} candidate(s) recorded, ${merged} merged, ${rejected} rejected`);
    for (const rejection of rejections) {
      write(style.dim(`  ${rejection.ruleId}: ${rejection.errors.join("; ")}`));
    }
  }

  return { candidates: result.candidates.length, created, merged, rejected, rejections, coverage: result.coverage };
}

/**
 * A candidate becomes a finding submission. The CLI owns identity, so no id is
 * supplied here; the intake assigns one and computes the fingerprint.
 */
export function toSubmission(candidate: Candidate): Record<string, unknown> {
  return {
    title: candidate.title,
    category: candidate.category,
    taxonomy: candidate.taxonomy,
    severity: candidate.severity,
    verification: candidate.verification,
    summary: candidate.summary,
    impact: candidate.impact,
    affected: {
      component: candidate.location.container ?? candidate.location.file,
      file: candidate.location.file,
      lineStart: candidate.location.line,
      ...(candidate.location.endLine ? { lineEnd: candidate.location.endLine } : {}),
      ...(candidate.route ? { route: candidate.route } : {})
    },
    evidence: [
      ...candidate.evidence,
      {
        kind: "source" as const,
        description: `Static analysis reasoning: ${candidate.reasoning}`
      }
    ],
    remediation: candidate.remediation,
    verificationPlan: candidate.verificationPlan,
    tags: ["static-pass", candidate.ruleId]
  };
}
