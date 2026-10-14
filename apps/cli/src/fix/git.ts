import { execFile } from "node:child_process";
import path from "node:path";
import { BRAND } from "@myrqen/brand";
import { findCredentialsInText } from "@myrqen/scan";
import { isSafeRepoRelativePath } from "../config/paths.js";

/**
 * The few git operations the fix loop needs, and nothing that can lose work.
 *
 * No reset, no checkout of files, no stash, no force, no push. The loop creates
 * one new branch from HEAD, and commits on that branch only. Every call goes
 * through `execFile` with an argv array, so a finding title or a branch name is
 * never interpreted by a shell.
 *
 * The repository is the one under assessment, and its configuration is not ours
 * to run. A `core.hooksPath` pointing into the repository (what husky and similar
 * tools set up on install) would run committed scripts on every commit and branch
 * switch the loop makes, and `core.fsmonitor` names a program `git status` runs.
 * Both are switched off for every call, the commit included: the loop's commit is
 * Myrqen's own bookkeeping on its own branch, and the user's hooks still run when
 * they commit, merge, or push that branch themselves.
 */

const NULL_DEVICE = process.platform === "win32" ? "NUL" : "/dev/null";

/** Prepended to every git call; see above. */
export const GIT_HARDENING: readonly string[] = Object.freeze([
  "-c",
  "core.fsmonitor=false",
  "-c",
  `core.hooksPath=${NULL_DEVICE}`
]);

interface GitResult {
  stdout: string;
  stderr: string;
  code: number;
}

export function git(cwd: string, args: string[], input?: string): Promise<GitResult> {
  return new Promise((resolve) => {
    const child = execFile(
      "git",
      [...GIT_HARDENING, ...args],
      { cwd, maxBuffer: 16 * 1024 * 1024, env: { ...process.env, GIT_TERMINAL_PROMPT: "0" } },
      (error, stdout, stderr) => {
        const code = error ? (typeof (error as { code?: unknown }).code === "number" ? Number((error as { code: number }).code) : 1) : 0;
        resolve({ stdout: String(stdout), stderr: String(stderr), code });
      }
    );
    if (input !== undefined) {
      child.stdin?.end(input);
    }
  });
}

async function ok(cwd: string, args: string[]): Promise<string> {
  const result = await git(cwd, args);
  if (result.code !== 0) {
    const detail = result.stderr.trim().split("\n").slice(-3).join(" ");
    throw new Error(`git ${args[0]} failed${detail ? `: ${detail}` : ""}`);
  }
  return result.stdout;
}

export async function gitRoot(cwd: string): Promise<string | null> {
  const result = await git(cwd, ["rev-parse", "--show-toplevel"]);
  return result.code === 0 ? path.resolve(result.stdout.trim()) : null;
}

/** The current branch, or null for a detached HEAD. */
export async function currentBranch(cwd: string): Promise<string | null> {
  const result = await git(cwd, ["symbolic-ref", "--quiet", "--short", "HEAD"]);
  return result.code === 0 ? result.stdout.trim() : null;
}

export async function headCommit(cwd: string): Promise<string | null> {
  const result = await git(cwd, ["rev-parse", "--verify", "--quiet", "HEAD"]);
  return result.code === 0 ? result.stdout.trim() : null;
}

export async function branchExists(cwd: string, name: string): Promise<boolean> {
  const result = await git(cwd, ["show-ref", "--verify", "--quiet", `refs/heads/${name}`]);
  return result.code === 0;
}

/** True for anything inside a state directory, at the top level or in a package. */
export function isStatePath(file: string): boolean {
  return file.replace(/\\/g, "/").split("/").includes(BRAND.repoStateDirectoryName);
}

/**
 * Paths with changes, staged, unstaged, or untracked — Myrqen's own state
 * directory excepted, since the loop writes there itself and never commits it.
 */
export async function changedPaths(cwd: string): Promise<string[]> {
  const output = await ok(cwd, ["status", "--porcelain=v1", "-z", "--untracked-files=all"]);
  const paths: string[] = [];
  const entries = output.split("\0");
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index]!;
    if (entry.length < 4) continue;
    const status = entry.slice(0, 2);
    const file = entry.slice(3);
    // A rename carries its source as the next NUL-separated field.
    if (status.startsWith("R") || status.startsWith("C")) index += 1;
    if (isStatePath(file)) continue;
    paths.push(file);
  }
  return paths;
}

export async function createBranch(cwd: string, name: string): Promise<void> {
  await ok(cwd, ["check-ref-format", "--branch", name]);
  await ok(cwd, ["switch", "--create", name]);
}

function nulList(output: string): string[] {
  return output.split("\0").filter((entry) => entry.length > 0);
}

/** A pathspec that matches exactly this top-relative path: no globbing, no magic. */
function literal(file: string): string {
  return `:(top,literal)${file}`;
}

/** Untracked files git does not ignore, relative to the top of the work tree, state directory excepted. */
export async function untrackedPaths(cwd: string): Promise<string[]> {
  const top = (await gitRoot(cwd)) ?? cwd;
  const output = await ok(top, ["ls-files", "--others", "--exclude-standard", "-z", "--", ":/"]);
  return nulList(output).filter((file) => !isStatePath(file));
}

export interface CredentialLocation {
  file: string;
  line: number;
  label: string;
}

/** A commit refused because the staged change carries something credential-shaped. */
export class CredentialInCommitError extends Error {
  constructor(readonly locations: CredentialLocation[]) {
    const shown = locations
      .slice(0, 10)
      .map((location) => `${location.file}:${location.line} (${location.label})`)
      .join(", ");
    const more = locations.length > 10 ? ` and ${locations.length - 10} more` : "";
    super(
      `Not committed: the change contains what looks like a credential at ${shown}${more}. The value is not shown here. Remove it from the code, rotate it if it is real, and retest again.`
    );
    this.name = "CredentialInCommitError";
  }
}

/** Added lines of the staged change, with their line numbers in the new file. */
async function stagedAdditions(top: string, file: string): Promise<Array<{ line: number; text: string }>> {
  const output = await ok(top, ["diff", "--cached", "--no-color", "--no-ext-diff", "--no-textconv", "-U0", "--", literal(file)]);
  const additions: Array<{ line: number; text: string }> = [];
  let next = 0;
  for (const row of output.split("\n")) {
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(row);
    if (hunk) {
      next = Number(hunk[1]);
      continue;
    }
    if (row.startsWith("+++") || !row.startsWith("+") || next === 0) continue;
    additions.push({ line: next, text: row.slice(1) });
    next += 1;
  }
  return additions;
}

/** Run the scanner's credential rule over every line the staged change adds. */
export async function credentialsInStagedChange(cwd: string): Promise<CredentialLocation[]> {
  const top = (await gitRoot(cwd)) ?? cwd;
  const staged = nulList(await ok(top, ["diff", "--cached", "--name-only", "--no-renames", "--diff-filter=AM", "-z"]));
  const locations: CredentialLocation[] = [];
  for (const file of staged) {
    for (const addition of await stagedAdditions(top, file)) {
      for (const hit of findCredentialsInText(addition.text)) {
        locations.push({ file, line: addition.line, label: hit.label });
      }
    }
  }
  return locations;
}

/**
 * Stage the fix and commit it, or explain why not.
 *
 * Only changes to files git already tracks are staged (`add --update`), plus any
 * file the fix plan names explicitly, plus whatever was deliberately added to the
 * index. Untracked files are left alone: between `fix` and `retest` an agent can
 * leave scratch files, logs, or captured responses in the tree, and a commit is
 * not the place to discover them. They are returned so the caller can name them.
 *
 * Before committing, the scanner's credential rule reads every added line; a hit
 * refuses the commit and names file and line, never the value. The message is
 * passed on stdin, so its contents never reach an argv a process list can show.
 */
export async function commitFixChanges(
  cwd: string,
  message: string,
  options: { explicitFiles?: readonly string[] } = {}
): Promise<{ sha: string | null; untracked: string[] }> {
  const top = (await gitRoot(cwd)) ?? cwd;
  await ok(top, ["add", "--update", "--", ":/", `:(top,exclude,glob)**/${BRAND.repoStateDirectoryName}/**`]);

  const untrackedBefore = new Set(await untrackedPaths(top));
  for (const file of options.explicitFiles ?? []) {
    if (!isSafeRepoRelativePath(file)) continue;
    const fromTop = path.relative(top, path.resolve(cwd, file)).split(path.sep).join("/");
    if (!fromTop || fromTop.startsWith("../") || fromTop === ".." || isStatePath(fromTop)) continue;
    if (untrackedBefore.has(fromTop)) await ok(top, ["add", "--", literal(fromTop)]);
  }
  const untracked = await untrackedPaths(top);

  const staged = nulList(await ok(top, ["diff", "--cached", "--name-only", "--no-renames", "-z"]));
  const stagedState = staged.filter((file) => isStatePath(file));
  if (stagedState.length > 0) {
    throw new Error(
      `Not committed: files inside ${BRAND.repoStateDirectoryName}/ are staged (${stagedState.slice(0, 5).join(", ")}). Unstage them; ${BRAND.displayName}'s own state is never committed.`
    );
  }
  if (staged.length === 0) return { sha: null, untracked };

  const credentials = await credentialsInStagedChange(top);
  if (credentials.length > 0) throw new CredentialInCommitError(credentials);

  const result = await git(top, ["commit", "--quiet", "--file", "-"], message);
  if (result.code !== 0) {
    const detail = (result.stderr || result.stdout).trim().split("\n").slice(-4).join(" ");
    throw new Error(`git commit failed${detail ? `: ${detail}` : ""}`);
  }
  return { sha: (await ok(top, ["rev-parse", "HEAD"])).trim(), untracked };
}
