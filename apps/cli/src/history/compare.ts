import crypto from "node:crypto";
import type { Finding, Severity, Verification } from "@myrqen/contracts";
import { computeFingerprint } from "@myrqen/policy";
import { findingIdentity } from "@myrqen/report";

/**
 * Comparing two runs by stable finding identity.
 *
 * A finding's id (`MYR-004`) is assigned per session and means nothing across
 * runs. The intake fingerprint merges duplicates inside a run, but it hashes the
 * summary text, and the static engine rewords a summary when unrelated code
 * nearby changes — measured on the vuln-shop fixture, where a one-line fix to a
 * path traversal re-fingerprinted an SSRF two handlers away. Across runs the
 * identity is therefore category, rule, and location (`locationFingerprinter`).
 *
 * The identity itself lives in `@myrqen/report` (identity.ts) and is shared with
 * the baseline and dashboard triage, so the three can never disagree.
 */

export interface FindingFingerprinter {
  fingerprint(finding: Finding): string;
}

/** The within-run dedupe identity. Includes the root-cause text, so it is too
 * sensitive across runs: an unrelated edit that changes how the engine words a
 * summary would read as one finding fixed and another introduced. */
export const intakeFingerprinter: FindingFingerprinter = {
  fingerprint: (finding) => finding.fingerprint ?? computeFingerprint(finding)
};

/**
 * Cross-run identity: the shared definition in `@myrqen/report` (identity.ts),
 * the same one the committed baseline and dashboard triage use. Two findings
 * that share it are told apart by `compareRuns`, which pairs them in order
 * rather than collapsing them.
 */
export const locationFingerprinter: FindingFingerprinter = {
  fingerprint: (finding) => findingIdentity(finding, "xr")
};

/** Key every finding, numbering repeats so two same-place findings stay two. */
function keyed(findings: readonly Finding[], fp: FindingFingerprinter): Map<string, Finding> {
  const ordered = [...findings].sort(
    // Optional chaining: an old or hand-edited session may carry a malformed finding.
    (left, right) => (left.affected?.lineStart ?? 0) - (right.affected?.lineStart ?? 0) || left.id.localeCompare(right.id)
  );
  const seen = new Map<string, number>();
  const out = new Map<string, Finding>();
  for (const finding of ordered) {
    const base = fp.fingerprint(finding);
    const count = seen.get(base) ?? 0;
    seen.set(base, count + 1);
    out.set(count === 0 ? base : `${base}#${count}`, finding);
  }
  return out;
}

export type DiffClass = "new" | "fixed" | "still_open" | "regressed";

export interface DiffEntry {
  fingerprint: string;
  title: string;
  severity: Severity;
  verification: Verification;
  /** The id in the newer run, when the finding is present there. */
  headId?: string;
  /** The id in the older run, when the finding is present there. */
  baseId?: string;
  /** Why a fixed entry counts as fixed. */
  reason?: "fixed_and_verified" | "no_longer_reported";
}

export interface RunDiff {
  new: DiffEntry[];
  fixed: DiffEntry[];
  stillOpen: DiffEntry[];
  regressed: DiffEntry[];
}

const CLOSED = new Set(["false_positive", "fixed_verified", "accepted_risk"]);

export function isOpen(finding: Finding): boolean {
  return !CLOSED.has(finding.status ?? "open");
}

function entry(finding: Finding, fingerprint: string, side: "head" | "base", other?: Finding): DiffEntry {
  return {
    fingerprint,
    title: finding.title,
    severity: finding.severity,
    verification: finding.verification,
    ...(side === "head" ? { headId: finding.id } : { baseId: finding.id }),
    ...(other ? (side === "head" ? { baseId: other.id } : { headId: other.id }) : {})
  };
}

const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function bySeverity(left: DiffEntry, right: DiffEntry): number {
  return (SEVERITY_RANK[left.severity] ?? 9) - (SEVERITY_RANK[right.severity] ?? 9) || left.title.localeCompare(right.title);
}

/**
 * Classify every finding of two runs.
 *
 * - new: open in head, never seen before (or only ever refuted).
 * - still_open: open in both.
 * - regressed: open in head, and marked fixed-and-verified in base or in any
 *   earlier run of `history`. A fix that came back is not "new".
 * - fixed: open in base and either verified fixed in head or no longer reported;
 *   or marked fixed in base by the fix loop and confirmed gone by head's scan.
 */
export function compareRuns(
  base: readonly Finding[],
  head: readonly Finding[],
  options: { history?: ReadonlyArray<readonly Finding[]>; fingerprinter?: FindingFingerprinter } = {}
): RunDiff {
  const fp = options.fingerprinter ?? locationFingerprinter;
  const baseBy = keyed(base, fp);
  const headBy = keyed(head, fp);
  const everFixed = new Set<string>();
  for (const run of options.history ?? []) {
    for (const [key, finding] of keyed(run, fp)) if (finding.status === "fixed_verified") everFixed.add(key);
  }

  const diff: RunDiff = { new: [], fixed: [], stillOpen: [], regressed: [] };

  for (const [fingerprint, finding] of headBy) {
    const before = baseBy.get(fingerprint);
    if (finding.status === "fixed_verified") {
      if (!before || isOpen(before) || before.status !== "fixed_verified") {
        diff.fixed.push({ ...entry(finding, fingerprint, "head", before), reason: "fixed_and_verified" });
      }
      continue;
    }
    if (!isOpen(finding)) continue;
    if (before && isOpen(before)) diff.stillOpen.push(entry(finding, fingerprint, "head", before));
    else if (before?.status === "fixed_verified" || (!before && everFixed.has(fingerprint))) {
      diff.regressed.push(entry(finding, fingerprint, "head", before));
    } else diff.new.push(entry(finding, fingerprint, "head", before));
  }

  for (const [fingerprint, finding] of baseBy) {
    if (headBy.has(fingerprint)) continue;
    // Open in base and gone now; or fixed by the fix loop after base was scanned,
    // and the newer scan confirms it is gone. A refuted finding was never open.
    if (!isOpen(finding) && finding.status !== "fixed_verified") continue;
    diff.fixed.push({ ...entry(finding, fingerprint, "base"), reason: "no_longer_reported" });
  }

  diff.new.sort(bySeverity);
  diff.fixed.sort(bySeverity);
  diff.stillOpen.sort(bySeverity);
  diff.regressed.sort(bySeverity);
  return diff;
}
