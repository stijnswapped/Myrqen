import { BRAND } from "@myrqen/brand";
import { findRepoRoot } from "../discovery/project.js";
import { compareRuns, type DiffEntry, type RunDiff } from "../history/compare.js";
import {
  listRuns,
  REPORT_FILES,
  reportPath,
  resolveRun,
  summarizeRun,
  type ReportFormat,
  type RunSummary
} from "../history/runs.js";
import type { SessionState } from "../session/state.js";
import { openExternal } from "../ui/open.js";
import { blank, field, heading, json, style, write } from "../ui/output.js";
import { isInteractive } from "../ui/prompt.js";
import { severityLine } from "../ui/progress.js";

export interface ReportOptions {
  asJson?: boolean;
  format?: string;
  list?: boolean;
  last?: number;
  open?: boolean;
}

const DEFAULT_LIST = 10;

function shortId(id: string): string {
  return id.replace(/^rpt_/, "").slice(0, 8);
}

function when(iso: string): string {
  return iso.slice(0, 16).replace("T", " ");
}

function parseFormat(value: string | undefined): ReportFormat | undefined {
  if (value === undefined) return undefined;
  const normalized = value.toLowerCase() === "markdown" ? "md" : value.toLowerCase();
  if (!(normalized in REPORT_FILES)) {
    throw new Error(`--format must be one of: ${Object.keys(REPORT_FILES).join(", ")}.`);
  }
  return normalized as ReportFormat;
}

function printRunTable(summaries: readonly RunSummary[]): void {
  for (const run of summaries) {
    const status = run.hasReport ? run.state : `${run.state}, no report yet`;
    write(
      `${style.bold(shortId(run.localReportId))}  ${when(run.createdAt)}  ${run.effort.padEnd(5)}  ${String(run.open).padStart(3)} open  ${String(run.verified).padStart(3)} verified  ${String(run.fixed).padStart(2)} fixed  ${style.dim(status)}`
    );
    write(style.dim(`          ${severityLine(run.severity)}`));
  }
}

/**
 * `report`: open the newest finished report, print one format's path, or list
 * recent runs. Opening a browser only happens in an attended terminal; an agent
 * gets the path and nothing launches on the user's screen behind its back.
 */
export async function reportCommand(reference: string | undefined, options: ReportOptions = {}): Promise<void> {
  const repoRoot = await findRepoRoot(process.cwd());
  const runs = await listRuns(repoRoot);

  if (options.list || options.last !== undefined) {
    const limit = options.last ?? DEFAULT_LIST;
    if (!Number.isInteger(limit) || limit < 1) throw new Error("--last takes a positive whole number.");
    const summaries = await Promise.all(runs.slice(0, limit).map((run) => summarizeRun(run)));
    if (options.asJson) {
      json({ total: runs.length, runs: summaries });
      return;
    }
    heading("recent runs");
    if (summaries.length === 0) {
      write(`No runs in ${repoRoot} yet. Start one with "${BRAND.cliName} auto".`);
      return;
    }
    printRunTable(summaries);
    blank();
    write(style.dim(`Open one with "${BRAND.cliName} report <id>", compare two with "${BRAND.cliName} diff <old> <new>".`));
    return;
  }

  const format = parseFormat(options.format);
  let run: SessionState | undefined;
  if (reference) {
    run = resolveRun(runs, reference);
    if (!(await summarizeRun(run)).hasReport) {
      throw new Error(
        `${run.localReportId} has no report files yet. Finish it with "${BRAND.cliName} --session ${run.localReportId} session finish".`
      );
    }
  } else {
    for (const candidate of runs) {
      if ((await summarizeRun(candidate)).hasReport) {
        run = candidate;
        break;
      }
    }
  }
  if (!run) {
    throw new Error(
      runs.length === 0
        ? `No runs in this repository yet. Start one with "${BRAND.cliName} auto".`
        : `No run has been finished yet, so there is no report to open. Finish the current one with "${BRAND.cliName} session finish".`
    );
  }

  const chosen = format ?? "html";
  const file = reportPath(run, chosen);
  const shouldOpen = !format && options.open !== false && !options.asJson && isInteractive();

  if (options.asJson) {
    json({ localReportId: run.localReportId, format: chosen, path: file, opened: false });
    return;
  }
  if (shouldOpen && openExternal(file)) {
    write(`${style.ok("Opened")} ${file}`);
  } else {
    write(file);
  }
}

function printSection(label: string, entries: readonly DiffEntry[], color: (value: string) => string): void {
  write(`${color(label)} ${style.dim(`(${entries.length})`)}`);
  for (const item of entries) {
    const id = item.headId ?? item.baseId ?? "";
    const reason = item.reason === "no_longer_reported" ? style.dim("  no longer reported") : "";
    write(`  ${item.severity.padEnd(8)} ${id.padEnd(8)} ${item.title}${reason}`);
  }
}

/**
 * `diff`: what changed between two runs, by stable fingerprint. With no
 * arguments it compares the two newest runs; with one, that run against the
 * newest.
 */
export async function diffCommand(
  baseReference: string | undefined,
  headReference: string | undefined,
  options: { asJson?: boolean } = {}
): Promise<RunDiff> {
  const repoRoot = await findRepoRoot(process.cwd());
  const runs = await listRuns(repoRoot);
  if (runs.length < 2 && !(baseReference && headReference)) {
    throw new Error(`A diff needs two runs and this repository has ${runs.length}. Run "${BRAND.cliName} auto" again after a change.`);
  }

  const head = headReference ? resolveRun(runs, headReference) : runs[0]!;
  const base = baseReference ? resolveRun(runs, baseReference) : runs[1]!;
  if (base.localReportId === head.localReportId) throw new Error("Those are the same run. Pick two different ones.");

  // Earlier runs inform "regressed": a fix that came back is not new.
  const history = runs.filter((run) => run.createdAt < base.createdAt).map((run) => run.findings);
  const diff = compareRuns(base.findings, head.findings, { history });

  if (options.asJson) {
    json({
      base: { localReportId: base.localReportId, createdAt: base.createdAt },
      head: { localReportId: head.localReportId, createdAt: head.createdAt },
      counts: {
        new: diff.new.length,
        fixed: diff.fixed.length,
        regressed: diff.regressed.length,
        stillOpen: diff.stillOpen.length
      },
      ...diff
    });
    return diff;
  }

  heading("diff");
  field("From", `${shortId(base.localReportId)}  ${when(base.createdAt)}  (${base.findings.length} findings)`);
  field("To", `${shortId(head.localReportId)}  ${when(head.createdAt)}  (${head.findings.length} findings)`);
  blank();
  printSection("New", diff.new, style.bad);
  printSection("Regressed", diff.regressed, style.bad);
  printSection("Fixed", diff.fixed, style.ok);
  printSection("Still open", diff.stillOpen, style.warn);
  return diff;
}
