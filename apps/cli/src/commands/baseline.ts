import fs from "node:fs/promises";
import path from "node:path";
import { BRAND } from "@myrqen/brand";
import type { ScanReport } from "@myrqen/contracts";
import { validateReport } from "@myrqen/contracts";
import {
  BASELINE_RELATIVE_PATH,
  compareToBaseline,
  createBaseline,
  parseBaseline,
  serializeBaseline,
  type BaselineFile
} from "@myrqen/report";
import { baselineFile, reportDirectory } from "../config/paths.js";
import { findRepoRoot } from "../discovery/project.js";
import { blank, field, heading, json, write } from "../ui/output.js";
import { listSessions } from "../session/state.js";

export interface BaselineCommandOptions {
  /** Local report id to take the baseline from. Defaults to the newest finished report. */
  from?: string;
  asJson?: boolean;
}

async function readReport(repoRoot: string, localReportId: string): Promise<ScanReport | null> {
  const file = path.join(reportDirectory(repoRoot, localReportId), "report.json");
  let raw: string;
  try {
    raw = await fs.readFile(file, "utf8");
  } catch {
    return null;
  }
  const parsed = validateReport(JSON.parse(raw));
  if (!parsed.valid || !parsed.value) {
    throw new Error(`The local report at ${file} does not match the supported report schema.`);
  }
  return parsed.value;
}

async function newestReport(repoRoot: string): Promise<ScanReport | null> {
  for (const session of await listSessions(repoRoot)) {
    const report = await readReport(repoRoot, session.localReportId);
    if (report) return report;
  }
  return null;
}

/** Reads an existing baseline, or null. A malformed one is an error, never overwritten silently. */
export async function readBaselineFile(repoRoot: string): Promise<BaselineFile | null> {
  let raw: string;
  try {
    raw = await fs.readFile(baselineFile(repoRoot), "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  }
  return parseBaseline(JSON.parse(raw));
}

/**
 * `myrqen baseline`: record the findings of a finished report as known, in a file
 * meant to be committed. Later reports mark each finding new or already known, and
 * list what has gone since.
 */
export async function baselineCommand(options: BaselineCommandOptions = {}): Promise<void> {
  const repoRoot = await findRepoRoot(process.cwd());
  const report = options.from ? await readReport(repoRoot, options.from) : await newestReport(repoRoot);
  if (!report) {
    throw new Error(
      options.from
        ? `No finished local report ${options.from} was found. List them with "${BRAND.cliName} reports".`
        : `No finished local report was found. Run "${BRAND.cliName} auto" and "${BRAND.cliName} session finish" first.`
    );
  }

  let previous: BaselineFile | null = null;
  try {
    previous = await readBaselineFile(repoRoot);
  } catch {
    // A malformed baseline is replaced: that is what the user asked for by running this.
    previous = null;
  }

  const baseline = createBaseline(report.findings, { fromReportId: report.id });
  const target = baselineFile(repoRoot);
  await fs.mkdir(path.dirname(target), { recursive: true });
  await fs.writeFile(target, serializeBaseline(baseline), { mode: 0o644 });

  const change = previous ? compareToBaseline(report.findings, previous).counts : null;
  if (options.asJson) {
    json({
      path: BASELINE_RELATIVE_PATH,
      fromReportId: report.id,
      entries: baseline.entries.length,
      ...(change ? { previous: { new: change.new, unchanged: change.unchanged, gone: change.fixed } } : {})
    });
    return;
  }

  heading("baseline");
  field("File", BASELINE_RELATIVE_PATH);
  field("From report", report.id);
  field("Findings recorded", String(baseline.entries.length));
  if (change) field("Since the previous baseline", `${change.new} new · ${change.unchanged} kept · ${change.fixed} gone`);
  blank();
  write("Commit this file. Later reports mark each finding as new or already in the baseline, and list what has gone.");
  write("A baselined finding is still a finding: the baseline records what is known, not what is accepted.");
}
