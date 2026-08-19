import { BRAND } from "@myrqen/brand";
import type {
  ExternalTargetDecision,
  Finding,
  FindingSubmissionResult,
  PhaseUpdateResult,
  ScanPhase,
  TokenSource
} from "@myrqen/contracts";
import {
  assertNoScopeExpansion,
  redactDeep,
  strongerVerification,
  buildAuthorizationPrompt,
  classifyPlannedAction,
  classifyRedirect,
  describeScopeRefusal,
  externalTargetPosture,
  intakeFinding,
  normalizeHttpTarget
} from "@myrqen/policy";
import type { PlannedAction } from "@myrqen/policy";
import { buildFixPrompt } from "@myrqen/report";
import { resolveClient } from "../api/client.js";
import { blank, bullet, field, json, style, warn, write } from "../ui/output.js";
import { confirm, isInteractive } from "../ui/prompt.js";
import { emitProgress, SAFE_PHASE_CODES } from "../session/sync.js";
import type { SessionState } from "../session/state.js";
import { loadKnownSecrets, markPhase, nextFindingId, saveSession } from "../session/state.js";
import { track } from "../api/telemetry.js";

export async function submitFinding(
  state: SessionState,
  raw: unknown,
  options: { asJson?: boolean; quiet?: boolean } = {}
): Promise<FindingSubmissionResult> {
  const knownSecrets = await loadKnownSecrets(state);
  state.candidateCount += 1;

  const { findings, result } = intakeFinding(state.findings, raw, {
    knownSecrets,
    nextId: () => nextFindingId(state)
  });

  if (!result.accepted) {
    // Roll the id counter back so a rejected submission does not burn an id.
    state.nextFindingSeq = Math.max(0, state.nextFindingSeq - 1);
    state.candidateCount -= 1;
    await saveSession(state);
    if (options.asJson) json(result);
    else if (!options.quiet) {
      warn("Finding rejected.");
      for (const error of result.errors) write(error);
    }
    return result;
  }

  if (result.action === "merged_as_corroboration") {
    state.nextFindingSeq = Math.max(0, state.nextFindingSeq - 1);
    state.duplicateCount += 1;
  }

  state.findings = findings;
  await saveSession(state);

  const { client } = await resolveClient();
  const validated = state.findings.filter((finding) => finding.verification === "verified").length;
  await emitProgress(state, client, {
    type: "aggregate_updated",
    safeCode: "VALIDATING_CANDIDATES",
    aggregate: { candidateCount: state.candidateCount, validatedCount: validated }
  });

  if (options.asJson) json(result);
  else if (!options.quiet) {
    if (result.action === "created") write(`${style.ok("Recorded")} ${result.findingId}`);
    else write(`${style.dim("Merged as corroboration into")} ${result.deduplicatedInto}`);
    for (const warning of result.warnings) write(style.dim(warning));
  }
  return result;
}

export async function updatePhase(
  state: SessionState,
  phase: ScanPhase,
  next: "running" | "complete",
  options: { asJson?: boolean } = {}
): Promise<PhaseUpdateResult> {
  const record = markPhase(state, phase, next);
  state.state = phase === "reporting" && next === "complete" ? "reporting" : mapPhaseToScanState(phase);
  await saveSession(state);

  const { client } = await resolveClient();
  const emitted = await emitProgress(state, client, {
    type: next === "running" ? "phase_started" : "phase_completed",
    phase,
    safeCode: SAFE_PHASE_CODES[phase],
    ...(record.durationMs !== undefined ? { durationMs: record.durationMs } : {})
  });

  const result: PhaseUpdateResult = { phase, state: next, cloudEventEmitted: emitted };
  if (options.asJson) json(result);
  else write(`${style.dim(next === "running" ? "phase started" : "phase complete")} ${phase}`);
  return result;
}

function mapPhaseToScanState(phase: ScanPhase): SessionState["state"] {
  switch (phase) {
    case "preflight":
      return "preflight";
    case "scope":
      return "scope";
    case "discovery":
      return "discovery";
    case "source_review":
    case "runtime_validation":
    case "access_control":
      return "assessment";
    case "validation":
      return "validation";
    case "reporting":
      return "reporting";
    default:
      return "assessment";
  }
}

/**
 * The authorization gate. An external origin is only ever authorized at exact
 * origin granularity, by an explicit human confirmation, and never inferred.
 */
export async function authorizeTarget(
  state: SessionState,
  input: string,
  options: { asJson?: boolean; grant?: boolean } = {}
): Promise<ExternalTargetDecision> {
  let normalized;
  try {
    normalized = normalizeHttpTarget(input);
  } catch (error) {
    const decision: ExternalTargetDecision = {
      target: input,
      normalizedOrigin: input,
      decision: "denied",
      reason: error instanceof Error ? error.message : "Not a valid http target."
    };
    if (options.asJson) json(decision);
    else warn(decision.reason ?? "Not a valid target.");
    return decision;
  }

  if (normalized.local) {
    const decision: ExternalTargetDecision = {
      target: input,
      normalizedOrigin: normalized.origin,
      decision: "local_no_authorization_needed",
      reason: "Local project services are in the intended scope."
    };
    if (options.asJson) json(decision);
    else write(`${style.ok("In scope")} ${normalized.origin} (local)`);
    return decision;
  }

  const already = state.scope.authorizedExternalTargets.some((target) => target.target === normalized.origin);
  if (already) {
    const decision: ExternalTargetDecision = {
      target: input,
      normalizedOrigin: normalized.origin,
      decision: "already_authorized"
    };
    if (options.asJson) json(decision);
    else write(`${style.ok("Authorized")} ${normalized.origin}`);
    return decision;
  }

  // Untrusted content must not be able to widen scope, even by persuading a human
  // to approve an origin that only it proposed.
  if (state.scope.injectionSuggestedOrigins?.includes(normalized.origin)) {
    const decision: ExternalTargetDecision = {
      target: input,
      normalizedOrigin: normalized.origin,
      decision: "denied",
      reason: `${normalized.origin} appears only in project content that also tried to instruct the scanner, so it cannot be authorized here. If this target is genuinely part of the project, add it to the project configuration and start a new session.`
    };
    if (!state.scope.deniedExternalTargets.includes(normalized.origin)) {
      state.scope.deniedExternalTargets.push(normalized.origin);
      await saveSession(state);
    }
    if (options.asJson) json(decision);
    else warn(decision.reason!);
    return decision;
  }

  const referenced = state.scope.pendingExternalCandidates.includes(normalized.origin);
  if (!referenced && !options.grant) {
    const decision: ExternalTargetDecision = {
      target: input,
      normalizedOrigin: normalized.origin,
      decision: "denied",
      reason: `${normalized.origin} is not referenced by this project's configuration or source, so it cannot be authorized here. Only project-related targets are eligible.`
    };
    if (options.asJson) json(decision);
    else warn(decision.reason!);
    return decision;
  }

  let granted = Boolean(options.grant);
  if (!granted) {
    if (!isInteractive()) {
      const decision: ExternalTargetDecision = {
        target: input,
        normalizedOrigin: normalized.origin,
        decision: "denied",
        reason: `Authorization for ${normalized.origin} requires an explicit confirmation. Ask the user "${buildAuthorizationPrompt(normalized.origin)}" and, only if they confirm, re-run with --grant.`
      };
      if (options.asJson) json(decision);
      else warn(decision.reason!);
      return decision;
    }
    if (normalized.privateNetwork) {
      write(
        style.dim(
          `${normalized.origin} is on a private network. It is treated as external and needs the same explicit authorization.`
        )
      );
    }
    granted = await confirm(buildAuthorizationPrompt(normalized.origin));
  }

  if (!granted) {
    if (!state.scope.deniedExternalTargets.includes(normalized.origin)) {
      state.scope.deniedExternalTargets.push(normalized.origin);
    }
    await saveSession(state);
    const { client } = await resolveClient();
    await emitProgress(state, client, { type: "warning_safe", safeCode: "EXTERNAL_TARGET_DECLINED" });
    const decision: ExternalTargetDecision = {
      target: input,
      normalizedOrigin: normalized.origin,
      decision: "denied",
      reason: "The user did not authorize this target. It will be recorded as not assessed."
    };
    if (options.asJson) json(decision);
    else write(style.dim(decision.reason!));
    return decision;
  }

  state.scope.authorizedExternalTargets.push({
    target: normalized.origin,
    authorized: true,
    authorizedAt: new Date().toISOString(),
    method: options.grant ? "interactive_confirmation" : "interactive_confirmation"
  });
  state.scope.pendingExternalCandidates = state.scope.pendingExternalCandidates.filter(
    (candidate) => candidate !== normalized.origin
  );
  await saveSession(state);

  const { client } = await resolveClient();
  await emitProgress(state, client, { type: "warning_safe", safeCode: "EXTERNAL_TARGET_AUTHORIZED" });

  const decision: ExternalTargetDecision = {
    target: input,
    normalizedOrigin: normalized.origin,
    decision: "authorized"
  };
  if (options.asJson) json({ ...decision, posture: externalTargetPosture() });
  else {
    write(`${style.ok("Authorized")} ${normalized.origin}`);
    const posture = externalTargetPosture();
    bullet(`Concurrency ${posture.maxConcurrency}, minimum delay ${posture.minDelayMs}ms`);
    bullet(`Permitted methods: ${posture.allowedMethods.join(", ")}`);
    bullet("Cross-origin redirects are not followed. Stop if production indicators appear.");
  }
  return decision;
}

export async function checkTargetInScope(state: SessionState, input: string, options: { asJson?: boolean } = {}): Promise<boolean> {
  const authorized = state.scope.authorizedExternalTargets.map((target) => target.target);
  try {
    assertNoScopeExpansion(input, authorized);
    if (options.asJson) json({ target: input, inScope: true });
    else write(`${style.ok("In scope")} ${input}`);
    return true;
  } catch (error) {
    const origin = (() => {
      try {
        return normalizeHttpTarget(input).origin;
      } catch {
        return input;
      }
    })();
    const message = describeScopeRefusal(origin, authorized);
    if (options.asJson) json({ target: input, inScope: false, reason: message });
    else warn(message);
    void error;
    return false;
  }
}

export function checkRedirect(state: SessionState, from: string, to: string, options: { asJson?: boolean } = {}): boolean {
  const authorized = state.scope.authorizedExternalTargets.map((target) => target.target);
  const decision = classifyRedirect(from, to, authorized);
  if (options.asJson) json(decision);
  else if (decision.decision === "follow") write(`${style.ok("Follow")} ${to}`);
  else warn(`Redirect to ${decision.origin} crosses the authorization boundary and must not be followed.`);
  return decision.decision === "follow";
}

/** Safety gate for any operation the agent proposes. */
export async function checkAction(
  state: SessionState,
  action: PlannedAction,
  options: { asJson?: boolean } = {}
): Promise<boolean> {
  const decision = classifyPlannedAction(action);
  state.actionLog.push({
    at: new Date().toISOString(),
    intent: action.intent,
    allowed: decision.allowed,
    ...(decision.violations.length > 0 ? { violations: decision.violations } : {})
  });
  await saveSession(state);

  if (options.asJson) json(decision);
  else if (decision.allowed) write(`${style.ok("Allowed")} ${action.intent}`);
  else {
    warn(decision.reason ?? "Blocked by safety policy.");
    if (decision.guidance) write(decision.guidance);
  }
  return decision.allowed;
}

export async function recordNote(
  state: SessionState,
  kind: "coverage" | "limitation",
  value: string,
  options: { area?: string; assessed?: boolean; asJson?: boolean } = {}
): Promise<void> {
  const trimmed = value.trim().slice(0, 1000);
  if (trimmed.length === 0) throw new Error("A note cannot be empty.");
  if (kind === "coverage") {
    state.coverage.push(trimmed);
    if (options.area) {
      state.coverageAreas.push({
        area: options.area,
        assessed: options.assessed ?? true,
        note: trimmed
      });
    }
  } else {
    state.limitations.push(trimmed);
    if (options.area) state.coverageAreas.push({ area: options.area, assessed: false, note: trimmed });
  }
  await saveSession(state);
  if (options.asJson) json({ kind, recorded: trimmed });
  else write(`${style.dim(kind === "coverage" ? "coverage" : "limitation")} recorded`);
}

/** Token usage always carries provenance. An exact count is never guessed. */
export async function recordTokenUsage(
  state: SessionState,
  source: TokenSource,
  count: number | undefined,
  estimator: string | undefined,
  options: { asJson?: boolean } = {}
): Promise<void> {
  if (source === "unavailable") {
    state.tokenUsage = { source: "unavailable" };
  } else {
    if (typeof count !== "number" || !Number.isFinite(count) || count < 0) {
      throw new Error(`A token count is required for source "${source}".`);
    }
    if (source === "estimated" && !estimator) {
      throw new Error("An estimated token count must name the estimator, for example --estimator transcript-v1.");
    }
    state.tokenUsage = { source, count: Math.round(count), ...(estimator ? { estimator } : {}) };
  }
  await saveSession(state);
  if (options.asJson) json(state.tokenUsage);
  else field("Token usage", `${state.tokenUsage.source}${state.tokenUsage.count ? ` ${state.tokenUsage.count}` : ""}`);
}

export async function recordAgentMetadata(
  state: SessionState,
  input: { name?: string; version?: string; model?: string },
  options: { asJson?: boolean } = {}
): Promise<void> {
  if (input.name) state.agent.name = input.name.slice(0, 120);
  if (input.version) state.agent.version = input.version.slice(0, 120);
  if (input.model) state.agent.model = input.model.slice(0, 200);
  await saveSession(state);
  if (options.asJson) json(state.agent);
  else field("Host agent", `${state.agent.name}${state.agent.model ? ` · ${state.agent.model}` : ""}`);
}

export function printFixPrompt(state: SessionState, findingId: string): void {
  const finding = state.findings.find((candidate) => candidate.id === findingId);
  if (!finding) {
    throw new Error(`Finding ${findingId} is not part of session ${state.localReportId}.`);
  }
  write(buildFixPrompt(finding, { projectName: state.project.name, localReportId: state.localReportId }));
}

export type FixAction = "suggested" | "applied" | "verified" | "verification_failed" | "reverted";

/**
 * Apply and verify bookkeeping. A finding is only marked fixed when the targeted
 * verification actually passed, and history is preserved either way.
 */
export async function recordFix(
  state: SessionState,
  findingId: string,
  action: FixAction,
  options: { changedFiles?: string[]; note?: string; asJson?: boolean } = {}
): Promise<Finding> {
  const finding = state.findings.find((candidate) => candidate.id === findingId);
  if (!finding) throw new Error(`Finding ${findingId} is not part of session ${state.localReportId}.`);

  const at = new Date().toISOString();
  finding.fixHistory = [
    ...(finding.fixHistory ?? []),
    {
      at,
      action,
      verified: action === "verified",
      ...(options.changedFiles && options.changedFiles.length > 0 ? { changedFiles: options.changedFiles } : {}),
      ...(options.note ? { note: options.note.slice(0, 4000) } : {})
    }
  ];

  if (action === "suggested") finding.status = "fix_suggested";
  if (action === "applied") finding.status = "fix_applied";
  if (action === "verified") {
    finding.status = "fixed_verified";
    finding.fixedAt = at;
  }
  if (action === "verification_failed") finding.status = "fix_applied";
  if (action === "reverted") finding.status = "open";

  await saveSession(state);
  await track({
    name: action === "suggested" ? "fix_prompt_copied" : action === "applied" ? "fix_apply_started" : "fix_verify_completed",
    client: "cli",
    ...(state.cloud.reportId ? { reportId: state.cloud.reportId } : {}),
    metrics: { fix_verified: action === "verified" }
  });

  if (options.asJson) json({ findingId, status: finding.status, verified: action === "verified" });
  else {
    write(
      action === "verified"
        ? `${style.ok("Fixed and verified")} ${findingId}`
        : action === "verification_failed"
          ? `${style.warn("Verification failed")} ${findingId} remains open`
          : `${style.dim(action)} recorded for ${findingId}`
    );
    if (action === "applied") {
      blank();
      write(
        `Run the targeted verification, then record the outcome with "${BRAND.cliName} fix record ${findingId} --verified" or "--verification-failed".`
      );
    }
  }
  return finding;
}

/**
 * Attach runtime evidence to an existing finding and raise its verification.
 *
 * Without this, an agent that confirms a static candidate has only one way to
 * say so: resubmit the whole finding. That only merges when the summary matches
 * byte for byte, so in practice a confirmation produced a second finding and the
 * report showed the same issue twice — once believed, once observed. Verification
 * is monotonic here: a confirmation can raise it and never lower it.
 */
export async function verifyFinding(
  state: SessionState,
  findingId: string,
  evidence: { kind?: string; description: string; location?: string; snippet?: string },
  options: { asJson?: boolean; quiet?: boolean } = {}
): Promise<Finding> {
  const finding = state.findings.find((candidate) => candidate.id === findingId);
  if (!finding) throw new Error(`Finding ${findingId} is not part of session ${state.localReportId}.`);
  if (!evidence.description?.trim()) {
    throw new Error("Verification needs a description of what was observed. State the request made and the response seen.");
  }

  const knownSecrets = await loadKnownSecrets(state);
  const redacted = redactDeep(
    {
      kind: (evidence.kind ?? "runtime") as Finding["evidence"][number]["kind"],
      description: evidence.description.trim().slice(0, 4000),
      ...(evidence.location ? { location: evidence.location.slice(0, 500) } : {}),
      ...(evidence.snippet ? { snippet: evidence.snippet.slice(0, 2000) } : {})
    },
    knownSecrets
  );

  finding.corroboration = [...(finding.corroboration ?? []), redacted.value];
  finding.verification = strongerVerification(finding.verification, "verified");
  await saveSession(state);

  const { client } = await resolveClient();
  const validated = state.findings.filter((candidate) => candidate.verification === "verified").length;
  await emitProgress(state, client, {
    type: "aggregate_updated",
    safeCode: "VALIDATING_CANDIDATES",
    aggregate: { candidateCount: state.candidateCount, validatedCount: validated }
  });

  if (options.asJson) json({ findingId, verification: finding.verification, corroboration: finding.corroboration.length });
  else if (!options.quiet) write(`${style.ok("Verified")} ${findingId} · ${validated} finding(s) now verified`);
  return finding;
}

/**
 * Mark a candidate the agent could not reproduce. The finding is kept, because a
 * silent deletion is indistinguishable from a scanner that never looked — but it
 * is labelled false_positive and carries the reason, so a reader can disagree.
 */
export async function refuteFinding(
  state: SessionState,
  findingId: string,
  reason: string,
  options: { asJson?: boolean; quiet?: boolean } = {}
): Promise<Finding> {
  const finding = state.findings.find((candidate) => candidate.id === findingId);
  if (!finding) throw new Error(`Finding ${findingId} is not part of session ${state.localReportId}.`);
  if (!reason.trim()) throw new Error("Refuting a finding needs a reason: say what was tried and what happened instead.");

  finding.status = "false_positive";
  finding.corroboration = [
    ...(finding.corroboration ?? []),
    { kind: "runtime", description: `Could not reproduce: ${reason.trim().slice(0, 4000)}` }
  ];
  await saveSession(state);

  if (options.asJson) json({ findingId, status: finding.status });
  else if (!options.quiet) write(`${style.dim("Refuted")} ${findingId}`);
  return finding;
}
