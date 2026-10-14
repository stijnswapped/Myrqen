import crypto from "node:crypto";
import type { Finding } from "@myrqen/contracts";
import { normalizeRoute } from "@myrqen/policy";
import { flowSink } from "./summary.js";

/**
 * A finding's identity across runs — the one definition every cross-run feature
 * uses: the committed baseline, `myrqen diff`, and dashboard triage.
 *
 * Three copies of this used to exist and disagreed: one fell back to the title,
 * one ignored the sink, one hashed the enclosing component even when a file and
 * route already located the finding. Titles and summaries are prose, and the
 * engine rewords prose when unrelated code nearby changes (measured on vuln-shop:
 * a one-line path-traversal fix reworded an SSRF two handlers away), so prose
 * never enters this key. Neither do line numbers, which move with every edit
 * above the finding.
 *
 * What does: the class, the static rule that raised it, the origin, the route
 * (method kept, concrete ids collapsed), the file, and the sink the evidence
 * names when it states a data flow ("X reaches Y") — the defect itself, parsed
 * from a structured pattern rather than read as prose.
 * The component name counts only when there is no file or route to locate the
 * finding by. Two findings that share all of that share an identity; callers
 * that must keep them apart number the repeats.
 */

const STATIC_TAG = "static-pass";
const ROUTE_METHOD = /^(get|post|put|patch|delete|head|options|all|any)$/i;

function normalizeFile(file: string | undefined): string {
  return file ? file.trim().replace(/\\/g, "/").replace(/^(\.\/)+/, "").replace(/\/{2,}/g, "/") : "";
}

function normalizeWords(value: string | undefined): string {
  return (value ?? "").toLowerCase().replace(/\s+/g, " ").trim();
}

function normalizeRouteWithMethod(route: string | undefined): string {
  const trimmed = (route ?? "").trim();
  if (!trimmed) return "";
  const match = /^([A-Za-z]+)\s+(\S.*)$/.exec(trimmed);
  if (match && ROUTE_METHOD.test(match[1] ?? "")) {
    return `${(match[1] ?? "").toUpperCase()} ${normalizeRoute(match[2] ?? "")}`;
  }
  return normalizeRoute(trimmed);
}

/** The static rule that raised a finding, or "" for an agent-reported one. */
export function staticRuleOf(finding: Pick<Finding, "tags">): string {
  const tags = finding.tags ?? [];
  return tags.includes(STATIC_TAG) ? (tags.find((tag) => tag !== STATIC_TAG) ?? "") : "";
}

/** The ordered, normalised fields the identity is computed from. */
export function findingIdentityMaterial(finding: Finding): string[] {
  const affected = finding.affected;
  const rule = staticRuleOf(finding);
  const file = normalizeFile(affected.file);
  const route = normalizeRouteWithMethod(affected.route);
  const sink = Array.isArray(finding.evidence) ? normalizeWords(flowSink(finding) ?? "") : "";
  return [
    normalizeWords(finding.category),
    rule,
    (affected.origin ?? "").trim().toLowerCase(),
    route,
    file,
    sink,
    file || route ? "" : normalizeWords(affected.component)
  ];
}

/** `<prefix>_<32 hex>`; the prefix names the consumer so keys are never mixed up. */
export function findingIdentity(finding: Finding, prefix: string): string {
  const digest = crypto.createHash("sha256").update(findingIdentityMaterial(finding).join("\u0000")).digest("hex");
  return `${prefix}_${digest.slice(0, 32)}`;
}
