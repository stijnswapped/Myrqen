import type { EffortProfile, EffortRequested, EffortResolved } from "@myrqen/contracts";

const MINUTE = 60_000;

/**
 * Effort is a policy profile: breadth, reasoning iterations, validation depth,
 * parallelism, and a practical time budget. It is never a token quota, and it
 * never changes what is authorized.
 */
export const EFFORT_PROFILES: Readonly<Record<EffortResolved, EffortProfile>> = Object.freeze({
  low: Object.freeze({
    reasoningPasses: 1,
    validationPasses: 1,
    maxParallelInvestigations: 2,
    wallClockBudgetMs: 8 * MINUTE,
    falsePositiveChallengePass: false,
    identityMatrixDepth: 1,
    breadth: "focused"
  }),
  high: Object.freeze({
    reasoningPasses: 2,
    validationPasses: 2,
    maxParallelInvestigations: 4,
    wallClockBudgetMs: 25 * MINUTE,
    falsePositiveChallengePass: true,
    identityMatrixDepth: 2,
    breadth: "broad"
  }),
  xhigh: Object.freeze({
    reasoningPasses: 3,
    validationPasses: 3,
    maxParallelInvestigations: 6,
    wallClockBudgetMs: 50 * MINUTE,
    falsePositiveChallengePass: true,
    identityMatrixDepth: 3,
    breadth: "broad"
  }),
  ultra: Object.freeze({
    reasoningPasses: 4,
    validationPasses: 4,
    maxParallelInvestigations: 8,
    wallClockBudgetMs: 110 * MINUTE,
    falsePositiveChallengePass: true,
    identityMatrixDepth: 3,
    breadth: "comprehensive"
  })
});

export interface ProjectSignals {
  /** Source files considered in scope (excludes vendored/build output). */
  sourceFileCount: number;
  /** Total bytes of in-scope source. */
  sourceByteCount: number;
  routeCount: number;
  hasAuthentication: boolean;
  hasRoles: boolean;
  hasDatabaseAccess: boolean;
  hasFileUpload: boolean;
  hasServerSideFetch: boolean;
  hasPaymentIntegration: boolean;
  runtimeReachable: boolean;
  testIdentityCount: number;
  externalTargetCount: number;
  isolatedRuntimeAvailable: boolean;
}

export interface EffortResolution {
  requested: EffortRequested;
  resolved: EffortResolved;
  profile: EffortProfile;
  rationale: string[];
}

function riskScore(signals: ProjectSignals): { score: number; notes: string[] } {
  const notes: string[] = [];
  let score = 0;

  if (signals.hasAuthentication) {
    score += 2;
    notes.push("Authentication implementation detected.");
  }
  if (signals.hasRoles) {
    score += 2;
    notes.push("Role or privilege separation detected.");
  }
  if (signals.hasDatabaseAccess) {
    score += 1;
    notes.push("Database access layer detected.");
  }
  if (signals.hasFileUpload) {
    score += 1;
    notes.push("File upload or download surface detected.");
  }
  if (signals.hasServerSideFetch) {
    score += 1;
    notes.push("Server-side outbound requests detected.");
  }
  if (signals.hasPaymentIntegration) {
    score += 2;
    notes.push("Payment or billing integration detected.");
  }
  if (signals.externalTargetCount > 0) {
    score += 1;
    notes.push(`${signals.externalTargetCount} external origin(s) referenced by project configuration.`);
  }
  if (signals.routeCount >= 60) {
    score += 2;
    notes.push(`${signals.routeCount} routes or endpoints mapped.`);
  } else if (signals.routeCount >= 20) {
    score += 1;
    notes.push(`${signals.routeCount} routes or endpoints mapped.`);
  }
  if (signals.sourceFileCount >= 900) {
    score += 2;
    notes.push("Large source tree.");
  } else if (signals.sourceFileCount >= 250) {
    score += 1;
    notes.push("Medium source tree.");
  }
  return { score, notes };
}

/**
 * `auto` inspects size, surface, and risk and records both the requested value
 * and the resolved policy so results stay comparable across runs.
 */
export function resolveEffort(requested: EffortRequested, signals: ProjectSignals): EffortResolution {
  if (requested !== "auto") {
    return {
      requested,
      resolved: requested,
      profile: EFFORT_PROFILES[requested],
      rationale: [`Explicit effort "${requested}" requested.`]
    };
  }

  const { score, notes } = riskScore(signals);
  let resolved: EffortResolved;
  if (score >= 9) resolved = "ultra";
  else if (score >= 6) resolved = "xhigh";
  else if (score >= 2) resolved = "high";
  else resolved = "low";

  const rationale = [`auto resolved to "${resolved}" (risk/surface score ${score}).`, ...notes];

  if (!signals.runtimeReachable) {
    rationale.push("No local runtime was reachable, so dynamic validation depth is reduced for this run.");
  }
  if (signals.testIdentityCount < 2) {
    rationale.push(
      "Fewer than two test identities are configured, so object-ownership comparisons may be limited."
    );
  }
  if (!signals.isolatedRuntimeAvailable) {
    rationale.push("Isolated runtime checks are unavailable on this machine; other checks still run.");
  }

  return { requested, resolved, profile: EFFORT_PROFILES[resolved], rationale };
}

/** Effort adjusts depth only. Safety and authorization are constant. */
export function assertEffortDoesNotWeakenSafety(profile: EffortProfile): void {
  if (profile.wallClockBudgetMs <= 0) throw new Error("Effort profile must define a terminating budget.");
  if (profile.maxParallelInvestigations < 1) throw new Error("Effort profile parallelism must be at least 1.");
}
