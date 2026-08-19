import crypto from "node:crypto";
import type { Finding, FindingEvidence } from "@myrqen/contracts";

function normalizeText(value: string): string {
  return value
    .toLowerCase()
    .replace(/[`'"]/g, "")
    .replace(/\b[0-9a-f]{8,}\b/g, "<hex>")
    .replace(/\b\d+\b/g, "<n>")
    .replace(/\s+/g, " ")
    .trim();
}

function normalizeLocation(finding: Pick<Finding, "affected">): string {
  const affected = finding.affected;
  const route = affected.route ? normalizeRoute(affected.route) : "";
  const file = affected.file ? affected.file.replace(/\\/g, "/").replace(/^\.\//, "") : "";
  const origin = affected.origin ?? "";
  return [origin, route, file, normalizeText(affected.component)].filter(Boolean).join("|");
}

/** Collapse concrete identifiers so /orders/12 and /orders/13 are one location. */
export function normalizeRoute(route: string): string {
  return route
    .replace(/\?.*$/, "")
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, ":id")
    .replace(/\/\d+(?=\/|$)/g, "/:id")
    .replace(/\/[0-9a-f]{16,}(?=\/|$)/gi, "/:id")
    .replace(/\/+$/, "")
    .toLowerCase();
}

/** Category + normalized location + root-cause identity. */
export function computeFingerprint(
  finding: Pick<Finding, "category" | "affected" | "summary" | "severity">
): string {
  const material = [
    finding.category.toLowerCase().trim(),
    normalizeLocation(finding),
    normalizeText(finding.summary).slice(0, 400)
  ].join("::");
  return `fp_${crypto.createHash("sha256").update(material).digest("hex").slice(0, 32)}`;
}

export interface DedupeOutcome {
  action: "created" | "merged_as_corroboration";
  fingerprint: string;
  mergedInto?: string;
}

/**
 * Alternate evidence for the same root cause becomes corroboration on the
 * existing finding rather than a second finding. Verification can only be
 * strengthened by a merge, never weakened.
 */
export function mergeOrCreate(
  existing: Finding[],
  candidate: Finding
): { findings: Finding[]; outcome: DedupeOutcome } {
  const fingerprint = candidate.fingerprint ?? computeFingerprint(candidate);
  const match = existing.find((finding) => (finding.fingerprint ?? computeFingerprint(finding)) === fingerprint);

  if (!match) {
    const created: Finding = { ...candidate, fingerprint };
    return { findings: [...existing, created], outcome: { action: "created", fingerprint } };
  }

  const newEvidence = candidate.evidence.filter(
    (item) => !hasEquivalentEvidence([...match.evidence, ...(match.corroboration ?? [])], item)
  );

  const merged: Finding = {
    ...match,
    severity: strongerSeverity(match.severity, candidate.severity),
    verification: strongerVerification(match.verification, candidate.verification),
    corroboration: [...(match.corroboration ?? []), ...newEvidence]
  };

  return {
    findings: existing.map((finding) => (finding.id === match.id ? merged : finding)),
    outcome: { action: "merged_as_corroboration", fingerprint, mergedInto: match.id }
  };
}

function hasEquivalentEvidence(pool: FindingEvidence[], candidate: FindingEvidence): boolean {
  const key = `${candidate.kind}::${normalizeText(candidate.description)}`;
  return pool.some((item) => `${item.kind}::${normalizeText(item.description)}` === key);
}

const SEVERITY_ORDER: Record<Finding["severity"], number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1
};

const VERIFICATION_ORDER: Record<Finding["verification"], number> = {
  verified: 3,
  strong_evidence: 2,
  needs_review: 1
};

export function strongerSeverity(a: Finding["severity"], b: Finding["severity"]): Finding["severity"] {
  return SEVERITY_ORDER[a] >= SEVERITY_ORDER[b] ? a : b;
}

export function strongerVerification(
  a: Finding["verification"],
  b: Finding["verification"]
): Finding["verification"] {
  return VERIFICATION_ORDER[a] >= VERIFICATION_ORDER[b] ? a : b;
}

export function severityRank(severity: Finding["severity"]): number {
  return SEVERITY_ORDER[severity];
}
