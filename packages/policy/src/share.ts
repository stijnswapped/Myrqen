import type {
  Finding,
  PrincipalType,
  ProjectionPolicy,
  ReportProjection,
  ScanReport,
  ShareConfig,
  ShareDenialReason,
  SharePrincipalRule,
  ShareResolution
} from "@myrqen/contracts";
import { severityRank } from "./dedupe.js";

export interface ViewerPrincipal {
  userId?: string;
  email?: string;
  workspaceIds?: string[];
  /** True only when no authenticated session exists. */
  anonymous: boolean;
}

export const DENY_ALL_POLICY: ProjectionPolicy = Object.freeze<ProjectionPolicy>({
  version: 1,
  sections: { mode: "allow_only", ids: [] },
  findings: { mode: "allow_only", ids: [] },
  fields: { evidence: false, code: false, reproduction: false, remediation: false, metadata: false }
});

export const OWNER_POLICY: ProjectionPolicy = Object.freeze<ProjectionPolicy>({
  version: 1,
  sections: { mode: "allow_all", ids: [] },
  findings: { mode: "allow_all", ids: [] },
  fields: { evidence: true, code: true, reproduction: true, remediation: true, metadata: true }
});

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

/**
 * Deny by default. The most specific matching rule wins: an explicit user id
 * beats an email rule, which beats a workspace rule, which beats anonymous.
 */
export function resolveSharePrincipal(
  share: Pick<ShareConfig, "mode" | "anonymousAllowed" | "defaultPolicy" | "principals" | "expiresAt" | "revokedAt" | "hasPassword">,
  viewer: ViewerPrincipal,
  options: { now?: Date; passwordVerified?: boolean; reportWorkspaceId?: string; isOwner?: boolean } = {}
): ShareResolution {
  const now = options.now ?? new Date();

  if (share.revokedAt) return deny("revoked");
  if (share.expiresAt && new Date(share.expiresAt).getTime() <= now.getTime()) return deny("expired");
  if (share.hasPassword && !options.passwordVerified) return { outcome: "password_required" };

  if (options.isOwner) {
    return { outcome: "allowed", policy: OWNER_POLICY, principalType: "user", label: "Report owner" };
  }

  const matched = matchPrincipalRule(share.principals, viewer);
  if (matched) {
    const label = matched.label ?? describePrincipal(matched);
    return { outcome: "allowed", policy: matched.policy, principalType: matched.principalType, label };
  }

  switch (share.mode) {
    case "private":
      return deny(viewer.anonymous ? "authentication_required" : "not_permitted");
    case "account_allowlist":
      // Only explicit principal rules grant access in allowlist mode.
      return deny(viewer.anonymous ? "authentication_required" : "not_permitted");
    case "workspace": {
      if (viewer.anonymous) return deny("authentication_required");
      const workspaceId = options.reportWorkspaceId;
      if (workspaceId && (viewer.workspaceIds ?? []).includes(workspaceId)) {
        return { outcome: "allowed", policy: share.defaultPolicy, principalType: "workspace", label: "Workspace member" };
      }
      return deny("not_permitted");
    }
    case "unlisted":
      if (viewer.anonymous) return deny("authentication_required");
      return { outcome: "allowed", policy: share.defaultPolicy, principalType: "user", label: "Link recipient" };
    case "anyone_with_link":
      if (viewer.anonymous && !share.anonymousAllowed) return deny("authentication_required");
      return {
        outcome: "allowed",
        policy: share.defaultPolicy,
        principalType: viewer.anonymous ? "anonymous" : "user",
        label: viewer.anonymous ? "Anonymous link viewer" : "Link recipient"
      };
    default:
      return deny("not_permitted");
  }
}

function deny(reason: ShareDenialReason): ShareResolution {
  return { outcome: "denied", reason };
}

function matchPrincipalRule(
  rules: readonly SharePrincipalRule[],
  viewer: ViewerPrincipal
): SharePrincipalRule | undefined {
  const byUser = rules.find(
    (rule) => rule.principalType === "user" && viewer.userId && rule.principalValue === viewer.userId
  );
  if (byUser) return byUser;

  if (viewer.email) {
    const email = normalizeEmail(viewer.email);
    const byEmail = rules.find(
      (rule) => rule.principalType === "email" && normalizeEmail(rule.principalValue ?? "") === email
    );
    if (byEmail) return byEmail;
  }

  const workspaceIds = viewer.workspaceIds ?? [];
  const byWorkspace = rules.find(
    (rule) => rule.principalType === "workspace" && rule.principalValue && workspaceIds.includes(rule.principalValue)
  );
  if (byWorkspace) return byWorkspace;

  if (viewer.anonymous) {
    const anonymous = rules.find((rule) => rule.principalType === "anonymous");
    if (anonymous) return anonymous;
  }
  return undefined;
}

function describePrincipal(rule: SharePrincipalRule): string {
  switch (rule.principalType) {
    case "user":
      return "Specific account";
    case "email":
      return rule.principalValue ?? "Invited account";
    case "workspace":
      return "Workspace member";
    case "anonymous":
      return "Anonymous link viewer";
    default:
      return "Viewer";
  }
}

function hasSection(policy: ProjectionPolicy, id: string): boolean {
  return policy.sections.mode === "allow_all" || policy.sections.ids.includes(id);
}

function projectFinding(finding: Finding, policy: ProjectionPolicy): Finding | null {
  if (policy.findings.mode === "allow_only" && !policy.findings.ids.includes(finding.id)) return null;
  if (policy.findings.maxSeverity && severityRank(finding.severity) > severityRank(policy.findings.maxSeverity)) {
    return null;
  }

  const out: Finding = {
    id: finding.id,
    title: finding.title,
    category: finding.category,
    severity: finding.severity,
    verification: finding.verification,
    summary: finding.summary,
    impact: finding.impact,
    affected: { ...finding.affected },
    evidence: [],
    remediation: "",
    verificationPlan: ""
  };

  if (finding.taxonomy) out.taxonomy = [...finding.taxonomy];
  if (finding.tags) out.tags = [...finding.tags];
  if (finding.status) out.status = finding.status;
  if (finding.fixedAt) out.fixedAt = finding.fixedAt;
  if (finding.fingerprint && policy.fields.metadata !== false) out.fingerprint = finding.fingerprint;
  if (finding.baselineState && policy.fields.metadata !== false) out.baselineState = finding.baselineState;

  const allowEvidence = policy.fields.evidence !== false;
  const allowCode = policy.fields.code !== false;
  if (allowEvidence) {
    out.evidence = finding.evidence.map((item) => stripEvidence(item, allowCode));
    if (finding.corroboration) out.corroboration = finding.corroboration.map((item) => stripEvidence(item, allowCode));
  } else {
    out.evidence = [{ kind: "other", description: "Evidence is not shared with this viewer.", redacted: true }];
  }

  out.remediation =
    policy.fields.remediation === false ? "Remediation guidance is not shared with this viewer." : finding.remediation;
  out.verificationPlan =
    policy.fields.remediation === false ? "Not shared with this viewer." : finding.verificationPlan;

  if (policy.fields.reproduction !== false && finding.reproduction) out.reproduction = finding.reproduction;
  if (policy.fields.metadata !== false && finding.references) out.references = [...finding.references];
  if (policy.fields.metadata !== false && finding.fixHistory) out.fixHistory = finding.fixHistory.map((e) => ({ ...e }));

  if (policy.anonymize) {
    out.affected = { component: anonymizeComponent(finding.affected.component) };
    delete out.reproduction;
    out.evidence = out.evidence.map((item) => {
      const anonymized = { ...item, redacted: true };
      delete anonymized.snippet;
      delete anonymized.location;
      return anonymized;
    });
    if (out.corroboration) {
      out.corroboration = out.corroboration.map((item) => {
        const anonymized = { ...item, redacted: true };
        delete anonymized.snippet;
        delete anonymized.location;
        return anonymized;
      });
    }
  }

  return out;
}

function stripEvidence(item: Finding["evidence"][number], allowCode: boolean): Finding["evidence"][number] {
  const out: Finding["evidence"][number] = { kind: item.kind, description: item.description };
  if (allowCode && item.snippet) out.snippet = item.snippet;
  if (!allowCode && item.snippet) out.redacted = true;
  if (item.location) out.location = item.location;
  if (item.redacted) out.redacted = true;
  return out;
}

function anonymizeComponent(component: string): string {
  return component.replace(/[A-Za-z0-9_.-]{2,}/g, (token) =>
    token.length <= 2 ? token : `${token[0]}${"*".repeat(Math.min(6, token.length - 1))}`
  );
}

/**
 * Security boundary. Call this before serialization to any response, export, or
 * cache entry. Callers must never place the canonical report next to the
 * projection in RSC payloads, logs, or preload data.
 */
export function projectReport(
  report: ScanReport,
  policy: ProjectionPolicy,
  principal: { principalType: PrincipalType; label?: string } = { principalType: "user" }
): ReportProjection {
  const projected: ReportProjection = {
    id: report.id,
    schemaVersion: report.schemaVersion,
    projectedFor: principal.label ? { principalType: principal.principalType, label: principal.label } : { principalType: principal.principalType }
  };

  const allowMetadata = hasSection(policy, "metadata") && policy.fields.metadata !== false;
  if (allowMetadata) {
    projected.generatedAt = report.generatedAt;
    projected.project = policy.anonymize
      ? { name: "Redacted project", workspaceKind: report.project.workspaceKind }
      : { ...report.project };
    projected.scan = policy.anonymize ? anonymizeScan(report.scan) : structuredClone(report.scan);
    if (report.authorization) projected.authorization = structuredClone(report.authorization);
    if (report.methodologyVersion) projected.methodologyVersion = report.methodologyVersion;
  }

  if (hasSection(policy, "summary")) projected.summary = { ...report.summary, severityCounts: { ...report.summary.severityCounts }, verificationCounts: { ...report.summary.verificationCounts } };

  if (hasSection(policy, "findings")) {
    projected.findings = report.findings
      .map((finding) => projectFinding(finding, policy))
      .filter((finding): finding is Finding => finding !== null);
    if (projected.summary) projected.summary = recount(projected.summary, projected.findings);
  }

  if (hasSection(policy, "coverage")) {
    projected.coverage = [...report.coverage];
    if (report.coverageAreas) projected.coverageAreas = report.coverageAreas.map((area) => ({ ...area }));
  }
  if (hasSection(policy, "limitations")) projected.limitations = [...report.limitations];

  if (policy.anonymize) {
    projected.redactionNotice = "This view is anonymized. Component names, code, and reproduction details are withheld.";
  } else if (policy.fields.evidence === false || policy.fields.code === false || policy.fields.remediation === false) {
    projected.redactionNotice = "Some sections of this report are not shared with you.";
  }

  return projected;
}

function anonymizeScan(scan: ScanReport["scan"]): ScanReport["scan"] {
  const clone = structuredClone(scan);
  clone.scope = { localTargets: [], externalTargets: [] };
  delete clone.host;
  return clone;
}

function recount(summary: NonNullable<ReportProjection["summary"]>, findings: Finding[]): NonNullable<ReportProjection["summary"]> {
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const verificationCounts = { verified: 0, strong_evidence: 0, needs_review: 0 };
  for (const finding of findings) {
    severityCounts[finding.severity] += 1;
    verificationCounts[finding.verification] += 1;
  }
  const out: NonNullable<ReportProjection["summary"]> = {
    findingCount: findings.length,
    severityCounts,
    verificationCounts
  };
  if (summary.fixedCount !== undefined) out.fixedCount = findings.filter((f) => f.status === "fixed_verified").length;
  return out;
}

/** Human-readable preview of what a principal will receive. */
export function describeProjection(policy: ProjectionPolicy, totalFindings: number): string[] {
  const lines: string[] = [];
  lines.push(
    policy.sections.mode === "allow_all"
      ? "Sections: all"
      : `Sections: ${policy.sections.ids.length > 0 ? policy.sections.ids.join(", ") : "none"}`
  );
  lines.push(
    policy.findings.mode === "allow_all"
      ? `Findings: all ${totalFindings}`
      : `Findings: ${policy.findings.ids.length} of ${totalFindings}`
  );
  const hidden = Object.entries(policy.fields)
    .filter(([, allowed]) => allowed === false)
    .map(([field]) => field);
  lines.push(hidden.length > 0 ? `Hidden fields: ${hidden.join(", ")}` : "Hidden fields: none");
  if (policy.anonymize) lines.push("Anonymized: component names, code, and reproduction removed");
  return lines;
}
