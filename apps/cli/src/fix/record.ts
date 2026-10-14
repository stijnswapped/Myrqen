import fs from "node:fs/promises";
import path from "node:path";
import { BRAND } from "@myrqen/brand";
import {
  assertFindingId,
  assertInsideStateDirectory,
  assertLocalReportId,
  isSafeRepoRelativePath,
  stateDirectory
} from "../config/paths.js";

/**
 * The fix loop's own bookkeeping, one file per finding per session, under
 * `.myrqen/fixes/` — excluded from git with the rest of the scan state, so
 * switching to the fix branch and back never touches it.
 */

export interface RetestRecord {
  at: string;
  outcome: "pass" | "fail" | "needs_runtime_evidence";
  static?: { ruleId: string; reproduced: boolean; matches: number };
  runtime?: { reproduced: boolean; evidence: string };
  summary: string;
}

export interface FixLoopRecord {
  version: 1;
  findingId: string;
  localReportId: string;
  branch: string;
  /** The branch the user was on; null when HEAD was detached. */
  baseBranch: string | null;
  baseCommit: string | null;
  mode: "deterministic" | "agent";
  createdAt: string;
  deterministic?: { files: string[]; summary: string[] };
  retests: RetestRecord[];
  commit?: { sha: string; at: string };
}

export function fixDirectory(repoRoot: string, localReportId: string, findingId: string): string {
  return assertInsideStateDirectory(
    repoRoot,
    path.join(stateDirectory(repoRoot), "fixes", assertLocalReportId(localReportId), assertFindingId(findingId))
  );
}

function recordFile(repoRoot: string, localReportId: string, findingId: string): string {
  return path.join(fixDirectory(repoRoot, localReportId, findingId), "fix.json");
}

export function fixBranchName(findingId: string): string {
  return `${BRAND.cliName}/fix-${assertFindingId(findingId)}`;
}

/**
 * The record for one finding, or null when the loop was never started for it.
 *
 * Like the rest of `.myrqen/`, the file sits in the scanned repository and may
 * have been committed by someone else. Its branch decides where a commit lands
 * and its file list decides what is staged, so a record that does not describe
 * exactly this finding on exactly its own branch is refused.
 */
export async function readFixRecord(repoRoot: string, localReportId: string, findingId: string): Promise<FixLoopRecord | null> {
  const file = recordFile(repoRoot, localReportId, findingId);
  let raw: string;
  try {
    raw = await fs.readFile(file, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw new Error(`The fix record at ${file} could not be read: ${(error as Error).message}`);
  }
  let parsed: Partial<FixLoopRecord>;
  try {
    parsed = JSON.parse(raw) as Partial<FixLoopRecord>;
  } catch {
    throw refused(file, "it is not valid JSON");
  }
  if (typeof parsed !== "object" || parsed === null || parsed.version !== 1) throw refused(file, "its version is not supported");
  if (parsed.findingId !== findingId || parsed.localReportId !== localReportId) throw refused(file, "it is for a different finding or session");
  if (parsed.branch !== fixBranchName(findingId)) throw refused(file, `its branch is not ${fixBranchName(findingId)}`);
  if (parsed.baseCommit !== null && (typeof parsed.baseCommit !== "string" || !/^[0-9a-f]{7,64}$/.test(parsed.baseCommit))) {
    throw refused(file, "its base commit is not a commit id");
  }
  if (parsed.deterministic !== undefined) {
    const files = parsed.deterministic?.files;
    if (!Array.isArray(files) || !files.every((entry) => isSafeRepoRelativePath(entry))) {
      throw refused(file, "it lists a changed file outside the repository");
    }
  }
  if (!Array.isArray(parsed.retests)) throw refused(file, "it has no retest history");
  return parsed as FixLoopRecord;
}

function refused(file: string, reason: string): Error {
  return new Error(
    `Refusing the fix record at ${file}: ${reason}. It is corrupted or was not written by ${BRAND.displayName}; remove that directory to start the fix over.`
  );
}

export async function writeFixRecord(repoRoot: string, record: FixLoopRecord): Promise<void> {
  const directory = fixDirectory(repoRoot, record.localReportId, record.findingId);
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  await fs.writeFile(recordFile(repoRoot, record.localReportId, record.findingId), `${JSON.stringify(record, null, 2)}\n`, {
    mode: 0o600
  });
}

export async function writeFixPlan(repoRoot: string, record: FixLoopRecord, markdown: string): Promise<string> {
  const directory = fixDirectory(repoRoot, record.localReportId, record.findingId);
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  const file = path.join(directory, "plan.md");
  await fs.writeFile(file, markdown, { mode: 0o600 });
  return file;
}
