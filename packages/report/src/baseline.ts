import crypto from "node:crypto";
import { CLI_VERSION } from "@myrqen/brand";
import type { Finding, Severity } from "@myrqen/contracts";
import { normalizeRoute } from "@myrqen/policy";
import { findingIdentity } from "./identity.js";

/**
 * A committable record of the findings a team has already seen, so the next report
 * can say which findings are new, which were already known, and which have gone.
 *
 * The file lives at `.myrqen/baseline.json`, outside the ignored report directories,
 * so it can be reviewed and committed like any other project file. It holds no
 * evidence and no code: only enough to recognise a finding again, plus a title a
 * reviewer can read in a diff. Titles are written after intake redaction, so the
 * file carries nothing the report itself would not.
 *
 * Matching uses a fingerprint built from what a finding *is* rather than where it
 * sits: its category, its file, the sink its evidence names, and its route. Line
 * numbers are left out on purpose, so adding an import at the top of a file does not
 * turn every known finding in it into a "new" one.
 */

export const BASELINE_SCHEMA = "myrqen-baseline/1";
export const BASELINE_RELATIVE_PATH = ".myrqen/baseline.json";

export interface BaselineEntry {
  fingerprint: string;
  category: string;
  title: string;
  severity: Severity;
  file?: string;
  route?: string;
}

export interface BaselineFile {
  schema: typeof BASELINE_SCHEMA;
  createdAt: string;
  /** The report the baseline was taken from. */
  fromReportId?: string;
  tool: { name: string; version: string };
  entries: BaselineEntry[];
}

/** SARIF's own vocabulary, so the SARIF writer can pass these straight through. */
export type BaselineState = "new" | "unchanged";

export interface BaselineComparison {
  baselineCreatedAt: string;
  fromReportId?: string;
  /** Present findings only: a finding already fixed or refuted has no state. */
  states: Record<string, BaselineState>;
  /** Known at baseline, not present now. */
  fixed: BaselineEntry[];
  counts: { new: number; unchanged: number; fixed: number };
}

function normalizeFile(file: string | undefined): string {
  return file ? file.replace(/\\/g, "/").replace(/^\.\//, "") : "";
}

/** Cross-run identity, shared with `myrqen diff` and dashboard triage: see identity.ts. */
export function baselineFingerprint(finding: Finding): string {
  return findingIdentity(finding, "bl");
}

/** A finding still standing: not fixed and verified, not refuted. Accepted risk stays. */
function isPresent(finding: Finding): boolean {
  return finding.status !== "fixed_verified" && finding.status !== "false_positive";
}

function entryFor(finding: Finding): BaselineEntry {
  const entry: BaselineEntry = {
    fingerprint: baselineFingerprint(finding),
    category: finding.category,
    title: finding.title,
    severity: finding.severity
  };
  if (finding.affected.file) entry.file = normalizeFile(finding.affected.file);
  if (finding.affected.route) entry.route = finding.affected.route;
  return entry;
}

function compareEntries(a: BaselineEntry, b: BaselineEntry): number {
  return (
    (a.file ?? "").localeCompare(b.file ?? "") ||
    a.category.localeCompare(b.category) ||
    a.fingerprint.localeCompare(b.fingerprint)
  );
}

export interface CreateBaselineOptions {
  now?: Date;
  fromReportId?: string;
}

/**
 * A baseline of every finding still standing in `findings`. Entries are sorted by
 * file, then category, so regenerating a baseline after one change produces a
 * one-line diff rather than a reshuffled file.
 */
export function createBaseline(findings: readonly Finding[], options: CreateBaselineOptions = {}): BaselineFile {
  const seen = new Set<string>();
  const entries: BaselineEntry[] = [];
  for (const finding of findings.filter(isPresent)) {
    const entry = entryFor(finding);
    if (seen.has(entry.fingerprint)) continue;
    seen.add(entry.fingerprint);
    entries.push(entry);
  }
  const baseline: BaselineFile = {
    schema: BASELINE_SCHEMA,
    createdAt: (options.now ?? new Date()).toISOString(),
    tool: { name: "myrqen", version: CLI_VERSION },
    entries: entries.sort(compareEntries)
  };
  if (options.fromReportId) baseline.fromReportId = options.fromReportId;
  return baseline;
}

export function compareToBaseline(findings: readonly Finding[], baseline: BaselineFile): BaselineComparison {
  const known = new Map(baseline.entries.map((entry) => [entry.fingerprint, entry]));
  const matched = new Set<string>();
  const states: Record<string, BaselineState> = {};
  let fresh = 0;
  let unchanged = 0;

  for (const finding of findings) {
    if (!isPresent(finding)) continue;
    const fingerprint = baselineFingerprint(finding);
    if (known.has(fingerprint)) {
      states[finding.id] = "unchanged";
      matched.add(fingerprint);
      unchanged += 1;
    } else {
      states[finding.id] = "new";
      fresh += 1;
    }
  }

  const fixed = baseline.entries.filter((entry) => !matched.has(entry.fingerprint)).sort(compareEntries);
  const comparison: BaselineComparison = {
    baselineCreatedAt: baseline.createdAt,
    states,
    fixed,
    counts: { new: fresh, unchanged, fixed: fixed.length }
  };
  if (baseline.fromReportId) comparison.fromReportId = baseline.fromReportId;
  return comparison;
}

const SEVERITIES: ReadonlySet<string> = new Set(["critical", "high", "medium", "low", "info"]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Reads a baseline someone may have edited by hand. Anything malformed is refused
 * with the reason, never half-read: a baseline that silently dropped entries would
 * report known findings as new, and one that kept garbage would hide real ones.
 */
export function parseBaseline(value: unknown): BaselineFile {
  if (!isRecord(value)) throw new Error("Baseline is not a JSON object.");
  if (value.schema !== BASELINE_SCHEMA) {
    throw new Error(`Baseline schema is ${JSON.stringify(value.schema)}, expected "${BASELINE_SCHEMA}".`);
  }
  if (typeof value.createdAt !== "string" || Number.isNaN(Date.parse(value.createdAt))) {
    throw new Error("Baseline createdAt is not a timestamp.");
  }
  if (!Array.isArray(value.entries)) throw new Error("Baseline entries is not a list.");
  const entries = value.entries.map((raw, index): BaselineEntry => {
    if (!isRecord(raw)) throw new Error(`Baseline entry ${index} is not an object.`);
    const { fingerprint, category, title, severity, file, route } = raw;
    if (typeof fingerprint !== "string" || !/^bl_[0-9a-f]{32}$/.test(fingerprint)) {
      throw new Error(`Baseline entry ${index} has no valid fingerprint.`);
    }
    if (typeof category !== "string" || typeof title !== "string") {
      throw new Error(`Baseline entry ${index} is missing its category or title.`);
    }
    if (typeof severity !== "string" || !SEVERITIES.has(severity)) {
      throw new Error(`Baseline entry ${index} has an unknown severity.`);
    }
    const entry: BaselineEntry = { fingerprint, category, title, severity: severity as Severity };
    if (typeof file === "string") entry.file = file;
    if (typeof route === "string") entry.route = route;
    return entry;
  });
  const tool = isRecord(value.tool) ? value.tool : {};
  const baseline: BaselineFile = {
    schema: BASELINE_SCHEMA,
    createdAt: value.createdAt,
    tool: {
      name: typeof tool.name === "string" ? tool.name : "myrqen",
      version: typeof tool.version === "string" ? tool.version : "unknown"
    },
    entries
  };
  if (typeof value.fromReportId === "string") baseline.fromReportId = value.fromReportId;
  return baseline;
}

/** Stable, reviewable serialization: two-space JSON with a trailing newline. */
export function serializeBaseline(baseline: BaselineFile): string {
  return `${JSON.stringify({ ...baseline, entries: [...baseline.entries].sort(compareEntries) }, null, 2)}\n`;
}
