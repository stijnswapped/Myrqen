import type { Finding, FindingSubmission, FindingSubmissionResult } from "@myrqen/contracts";
import { formatIssues, validateFinding, validateFindingSubmission } from "@myrqen/contracts";
import { computeFingerprint, mergeOrCreate } from "./dedupe.js";
import { containsSecretLikeMaterial, redactDeep } from "./redaction.js";

export interface IntakeOptions {
  /** Secret values known to exist locally (for example parsed from .env). */
  knownSecrets: readonly string[];
  /** Monotonic id allocator so ids are stable and human-referencable. */
  nextId: () => string;
  now?: () => Date;
}

const SEVERITY_INFLATION_CATEGORIES = new Set([
  "missing_security_header",
  "verbose_error_message",
  "outdated_dependency_no_known_exploit_path"
]);

/**
 * Findings arrive from the host agent as untrusted-shaped data. The CLI owns
 * validation, redaction, normalization, identity, and dedupe so a report can
 * never contain a raw secret or an agent-chosen id.
 */
export function intakeFinding(
  existing: Finding[],
  submission: unknown,
  options: IntakeOptions
): { findings: Finding[]; result: FindingSubmissionResult } {
  const warnings: string[] = [];
  const errors: string[] = [];

  const schemaCheck = validateFindingSubmission(submission);
  if (!schemaCheck.valid || !schemaCheck.value) {
    return {
      findings: existing,
      result: {
        accepted: false,
        action: "rejected",
        warnings,
        errors: [
          "Finding rejected: it does not match schemas/finding-submission.schema.json.",
          formatIssues(schemaCheck.issues)
        ].filter(Boolean),
        redactions: 0
      }
    };
  }

  const accepted: FindingSubmission = schemaCheck.value;
  const now = (options.now ?? (() => new Date()))().toISOString();

  // Redact until the value stops changing. One pass is enough for every pattern
  // in use today, but a pattern that matched its own output would otherwise
  // reject every finding that tripped it — losing real vulnerabilities because
  // of how their evidence happened to be worded.
  let clean = accepted;
  let redactionCount = 0;
  for (let pass = 0; pass < 3; pass += 1) {
    const step = redactDeep(clean, options.knownSecrets);
    redactionCount += step.replacements;
    clean = step.value;
    if (step.replacements === 0) break;
  }
  const redaction = { replacements: redactionCount };
  if (redaction.replacements > 0) {
    warnings.push(
      `${redaction.replacements} secret-like value(s) were redacted from this finding before it was stored.`
    );
  }

  // Second pass: if anything still looks like a live credential, refuse.
  const serialized = JSON.stringify(clean);
  if (containsSecretLikeMaterial(serialized, options.knownSecrets)) {
    errors.push(
      "Finding rejected: it still contains secret-like material after redaction. Describe the secret by location and type instead of including its value."
    );
    return { findings: existing, result: { accepted: false, action: "rejected", warnings, errors, redactions: redaction.replacements } };
  }

  const normalizedSeverity = normalizeSeverity(clean, warnings);

  const candidate: Finding = {
    id: options.nextId(),
    title: clean.title.trim(),
    category: normalizeCategory(clean.category),
    severity: normalizedSeverity,
    verification: clean.verification,
    summary: clean.summary.trim(),
    impact: clean.impact.trim(),
    affected: clean.affected,
    evidence: clean.evidence,
    remediation: clean.remediation.trim(),
    verificationPlan: clean.verificationPlan.trim(),
    status: "open",
    firstSeenAt: now
  };
  if (clean.taxonomy) candidate.taxonomy = clean.taxonomy;
  if (clean.reproduction) candidate.reproduction = clean.reproduction;
  if (clean.references) candidate.references = clean.references;
  if (clean.tags) candidate.tags = clean.tags;
  candidate.fingerprint = computeFingerprint(candidate);

  const finalCheck = validateFinding(candidate);
  if (!finalCheck.valid) {
    errors.push("Internal error: normalized finding failed report schema validation.", formatIssues(finalCheck.issues));
    return { findings: existing, result: { accepted: false, action: "rejected", warnings, errors, redactions: redaction.replacements } };
  }

  const { findings, outcome } = mergeOrCreate(existing, candidate);
  const result: FindingSubmissionResult = {
    accepted: true,
    action: outcome.action,
    fingerprint: outcome.fingerprint,
    warnings,
    errors,
    redactions: redaction.replacements
  };
  if (outcome.action === "created") result.findingId = candidate.id;
  else if (outcome.mergedInto) {
    result.findingId = outcome.mergedInto;
    result.deduplicatedInto = outcome.mergedInto;
  }
  return { findings, result };
}

function normalizeCategory(category: string): string {
  return category
    .trim()
    .toLowerCase()
    .replace(/[\s-]+/g, "_")
    .replace(/[^a-z0-9_]/g, "")
    .slice(0, 120);
}

/**
 * Severity reflects realistic impact in the assessed context. Categories that
 * are commonly over-rated are capped unless runtime evidence is present.
 */
function normalizeSeverity(submission: FindingSubmission, warnings: string[]): Finding["severity"] {
  const category = normalizeCategory(submission.category);
  const hasRuntimeEvidence = submission.evidence.some(
    (item) => item.kind === "runtime" || item.kind === "identity_differential"
  );

  if (SEVERITY_INFLATION_CATEGORIES.has(category) && !hasRuntimeEvidence) {
    if (submission.severity === "critical" || submission.severity === "high") {
      warnings.push(
        `Severity for category "${category}" was reduced to medium because no runtime or differential evidence was supplied.`
      );
      return "medium";
    }
  }

  if (submission.verification === "needs_review" && submission.severity === "critical") {
    warnings.push(
      "Severity critical with verification needs_review was reduced to high. Validate the issue to restore critical."
    );
    return "high";
  }

  return submission.severity;
}

export function summarize(findings: Finding[]): {
  findingCount: number;
  severityCounts: Record<Finding["severity"], number>;
  verificationCounts: Record<Finding["verification"], number>;
} {
  const severityCounts: Record<Finding["severity"], number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };
  const verificationCounts: Record<Finding["verification"], number> = {
    verified: 0,
    strong_evidence: 0,
    needs_review: 0
  };
  for (const finding of findings) {
    severityCounts[finding.severity] += 1;
    verificationCounts[finding.verification] += 1;
  }
  return { findingCount: findings.length, severityCounts, verificationCounts };
}
