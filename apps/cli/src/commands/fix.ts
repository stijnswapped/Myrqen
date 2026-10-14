import fs from "node:fs/promises";
import path from "node:path";
import { BRAND } from "@myrqen/brand";
import type { Finding } from "@myrqen/contracts";
import { recordFix } from "../agent/protocol.js";
import { planDeterministicFix, type DeterministicPlan } from "../fix/deterministic.js";
import {
  branchExists,
  changedPaths,
  commitFixChanges,
  createBranch,
  CredentialInCommitError,
  currentBranch,
  gitRoot,
  headCommit,
  untrackedPaths,
  type CredentialLocation
} from "../fix/git.js";
import { buildFixPlan, type FixPlan } from "../fix/plan.js";
import {
  fixBranchName,
  fixDirectory,
  readFixRecord,
  writeFixPlan,
  writeFixRecord,
  type FixLoopRecord,
  type RetestRecord
} from "../fix/record.js";
import { retestFinding } from "../fix/retest.js";
import { refreshLocalReport } from "../session/finish.js";
import { saveSession, type SessionState } from "../session/state.js";
import { blank, bullet, field, heading, json, style, write } from "../ui/output.js";

/**
 * The fix loop: one finding, one branch, one commit that only lands after a
 * retest passes.
 *
 * `fix <id>` refuses a dirty tree, branches from HEAD as `myrqen/fix-<id>`, and
 * either applies a mechanical fix (a dependency bump inside its major) or writes
 * a plan and prompt for the host agent. `retest <id>` re-runs only that finding's
 * check; on a pass it commits on the fix branch and marks the finding fixed and
 * verified. Nothing here pushes, and nothing commits to the branch the user
 * started on.
 */

export const EXIT_NEEDS_EVIDENCE = 5;
export const EXIT_RETEST_FAILED = 6;

export { fixBranchName };

function findFinding(state: SessionState, findingId: string): Finding {
  const finding = state.findings.find((candidate) => candidate.id === findingId.toUpperCase() || candidate.id === findingId);
  if (!finding) {
    throw new Error(
      `Finding ${findingId} is not part of session ${state.localReportId}. List them with "${BRAND.cliName} finding list --all".`
    );
  }
  return finding;
}

async function requireGit(state: SessionState): Promise<string> {
  const root = await gitRoot(state.repoRoot);
  if (!root) {
    throw new Error(
      `${state.repoRoot} is not a git repository. The fix loop works on its own branch so your work is never mixed with it; run "git init" and commit first, or use "${BRAND.cliName} fix prompt <id>" to fix by hand.`
    );
  }
  return root;
}

async function savePlanFiles(repoRoot: string, record: FixLoopRecord, plan: FixPlan): Promise<string> {
  const file = await writeFixPlan(repoRoot, record, `${plan.prompt}\n`);
  await fs.writeFile(path.join(fixDirectory(repoRoot, record.localReportId, record.findingId), "plan.json"), `${JSON.stringify(plan, null, 2)}\n`, {
    mode: 0o600
  });
  return file;
}

async function readPlan(repoRoot: string, record: FixLoopRecord): Promise<FixPlan | null> {
  try {
    return JSON.parse(
      await fs.readFile(path.join(fixDirectory(repoRoot, record.localReportId, record.findingId), "plan.json"), "utf8")
    ) as FixPlan;
  } catch {
    return null;
  }
}

function printPlan(plan: FixPlan, planFile: string, resumed: boolean): void {
  heading(resumed ? `fix ${plan.findingId} (continuing)` : `fix ${plan.findingId}`);
  field("Finding", `${plan.title} · ${plan.severity} · ${plan.verification.replaceAll("_", " ")}`);
  field("Branch", `${plan.branch} (from ${plan.baseBranch ?? "detached HEAD"})`);
  field("Mode", plan.mode === "deterministic" ? `mechanical fix applied by ${BRAND.displayName}` : "host agent edits the code");
  if (plan.targets.length > 0) field("Targets", plan.targets.join(", "));
  for (const edit of plan.appliedEdits) bullet(`${style.ok("applied")} ${edit}`);
  blank();
  write(style.bold("Plan"));
  plan.steps.forEach((step, index) => write(`  ${index + 1}. ${step}`));
  blank();
  write(style.bold("Prompt for the host agent"));
  write(plan.prompt);
  blank();
  write(style.dim(`Saved to ${planFile}`));
}

export async function fixCommand(state: SessionState, findingId: string, options: { asJson?: boolean } = {}): Promise<FixPlan> {
  const finding = findFinding(state, findingId);
  if (finding.status === "false_positive") {
    throw new Error(`${finding.id} was refuted as a false positive, so there is nothing to fix.`);
  }
  if (finding.status === "fixed_verified") {
    throw new Error(`${finding.id} is already fixed and verified.`);
  }

  await requireGit(state);
  const branch = fixBranchName(finding.id);
  const onBranch = await currentBranch(state.repoRoot);
  const existing = await readFixRecord(state.repoRoot, state.localReportId, finding.id);

  // Running `fix` again on the fix branch continues the loop rather than refusing.
  if (existing && onBranch === existing.branch) {
    const plan = await readPlan(state.repoRoot, existing);
    if (plan) {
      if (options.asJson) json({ ...plan, resumed: true, planFile: path.join(fixDirectory(state.repoRoot, existing.localReportId, existing.findingId), "plan.md") });
      else printPlan(plan, path.join(fixDirectory(state.repoRoot, existing.localReportId, existing.findingId), "plan.md"), true);
      return plan;
    }
  }

  const dirty = await changedPaths(state.repoRoot);
  if (dirty.length > 0) {
    const shown = dirty.slice(0, 8).map((file) => `  ${file}`).join("\n");
    const more = dirty.length > 8 ? `\n  …and ${dirty.length - 8} more` : "";
    throw new Error(
      `Your working tree has uncommitted changes, so ${BRAND.displayName} will not start a fix branch:\n${shown}${more}\nCommit or stash them first. The fix goes on its own branch and its own commit, and must not carry your unrelated work with it.`
    );
  }
  if (await branchExists(state.repoRoot, branch)) {
    throw new Error(
      `Branch ${branch} already exists. Switch to it with "git switch ${branch}" and run "${BRAND.cliName} fix ${finding.id}" to continue, or delete it to start over.`
    );
  }

  const baseCommit = await headCommit(state.repoRoot);
  if (!baseCommit) throw new Error("This repository has no commits yet. Commit once before starting a fix branch.");
  await createBranch(state.repoRoot, branch);

  const deterministic: DeterministicPlan | null = await planDeterministicFix(state.repoRoot, finding);
  let appliedFiles: string[] = [];
  if (deterministic.applicable && deterministic.apply) appliedFiles = await deterministic.apply();

  const record: FixLoopRecord = {
    version: 1,
    findingId: finding.id,
    localReportId: state.localReportId,
    branch,
    baseBranch: onBranch,
    baseCommit,
    mode: appliedFiles.length > 0 ? "deterministic" : "agent",
    createdAt: new Date().toISOString(),
    ...(appliedFiles.length > 0
      ? { deterministic: { files: appliedFiles, summary: deterministic.edits.map((edit) => edit.description) } }
      : {}),
    retests: []
  };
  await writeFixRecord(state.repoRoot, record);

  await recordFix(state, finding.id, appliedFiles.length > 0 ? "applied" : "suggested", {
    quiet: true,
    ...(appliedFiles.length > 0 ? { changedFiles: appliedFiles } : {}),
    note: `Fix loop started on ${branch} from ${onBranch ?? "detached HEAD"}@${baseCommit.slice(0, 7)}.`
  });

  const plan = buildFixPlan(finding, record, deterministic.applicable ? deterministic : null, { projectName: state.project.name });
  const planFile = await savePlanFiles(state.repoRoot, record, plan);
  if (options.asJson) json({ ...plan, resumed: false, planFile });
  else printPlan(plan, planFile, false);
  return plan;
}

function commitMessage(finding: Finding, record: FixLoopRecord | null, retest: RetestRecord, localReportId: string): string {
  const lines = [
    `fix(security): ${finding.title} (${finding.id})`,
    "",
    `Retest evidence (${BRAND.displayName} ${localReportId}):`,
    ...retest.summary.split("\n").map((line) => `- ${line}`)
  ];
  if (record?.baseCommit) lines.push("", `Branched from ${record.baseBranch ?? "detached HEAD"} at ${record.baseCommit.slice(0, 12)}.`);
  return `${lines.join("\n")}\n`;
}

export interface RetestOutcome {
  findingId: string;
  outcome: RetestRecord["outcome"];
  summary: string;
  status: string;
  committed?: { sha: string; branch: string };
  commitSkipped?: string;
  /** Untracked files left out of the commit; never added automatically. */
  untracked?: string[];
  /** Where the staged change looked like it carried a credential; the value is never included. */
  credentialsFound?: CredentialLocation[];
  reportRefreshed: boolean;
}

export async function retestCommand(
  state: SessionState,
  findingId: string,
  options: { asJson?: boolean; evidence?: string; stillReproduces?: boolean; commit?: boolean } = {}
): Promise<RetestOutcome> {
  const finding = findFinding(state, findingId);
  if (finding.status === "false_positive") throw new Error(`${finding.id} was refuted as a false positive; there is nothing to retest.`);

  const retest = await retestFinding(state, finding, {
    ...(options.evidence ? { evidence: options.evidence } : {}),
    ...(options.stillReproduces ? { stillReproduces: true } : {})
  });
  const record = await readFixRecord(state.repoRoot, state.localReportId, finding.id);
  if (record) {
    record.retests.push(retest);
    await writeFixRecord(state.repoRoot, record);
  }

  const outcome: RetestOutcome = {
    findingId: finding.id,
    outcome: retest.outcome,
    summary: retest.summary,
    status: finding.status ?? "open",
    reportRefreshed: false
  };

  if (retest.outcome === "fail") {
    await recordFix(state, finding.id, "verification_failed", { quiet: true, note: retest.summary });
  }

  if (retest.outcome === "pass") {
    // Commit first: if the commit is refused (a credential in the change, a git
    // error), the finding is still verified, and the reason the commit did not
    // land is reported rather than swallowed.
    const branch = await currentBranch(state.repoRoot).catch(() => null);
    if (options.commit === false) {
      outcome.commitSkipped = "--no-commit was given.";
    } else if (!record) {
      outcome.commitSkipped = `No fix branch was started for ${finding.id}, so nothing was committed. "${BRAND.cliName} fix ${finding.id}" starts one.`;
    } else if (branch !== record.branch) {
      outcome.commitSkipped = `You are on ${branch ?? "a detached HEAD"}, not ${record.branch}. ${BRAND.displayName} only commits on the fix branch.`;
    } else {
      const changed = await changedPaths(state.repoRoot);
      if (changed.length === 0) {
        outcome.commitSkipped = "There were no changes to commit.";
      } else {
        try {
          const explicitFiles = [...(record.deterministic?.files ?? []), ...(finding.affected.file ? [finding.affected.file] : [])];
          const result = await commitFixChanges(state.repoRoot, commitMessage(finding, record, retest, state.localReportId), {
            explicitFiles
          });
          if (result.untracked.length > 0) outcome.untracked = result.untracked;
          if (result.sha) {
            record.commit = { sha: result.sha, at: new Date().toISOString() };
            await writeFixRecord(state.repoRoot, record);
            outcome.committed = { sha: result.sha, branch: record.branch };
          } else {
            outcome.commitSkipped = "Only untracked files changed, and those are never added automatically. Stage the ones that belong to the fix with \"git add <file>\" and retest again.";
          }
        } catch (error) {
          if (error instanceof CredentialInCommitError) outcome.credentialsFound = error.locations;
          outcome.commitSkipped = error instanceof Error ? error.message : "git commit failed.";
        }
        if (!outcome.untracked) {
          const untracked = await untrackedPaths(state.repoRoot).catch(() => []);
          if (untracked.length > 0) outcome.untracked = untracked;
        }
      }
    }
    await recordFix(state, finding.id, "verified", {
      quiet: true,
      ...(record?.deterministic ? { changedFiles: record.deterministic.files } : {}),
      note: `${retest.summary}${outcome.committed ? `\ncommitted ${outcome.committed.sha.slice(0, 12)} on ${outcome.committed.branch}` : ""}`
    });
  }

  outcome.status = finding.status ?? "open";
  await saveSession(state);
  outcome.reportRefreshed = await refreshLocalReport(state);

  if (options.asJson) {
    json(outcome);
    return outcome;
  }

  heading(`retest ${finding.id}`);
  for (const line of retest.summary.split("\n")) bullet(line);
  blank();
  if (retest.outcome === "pass") {
    write(`${style.ok("Fixed and verified")} ${finding.id}`);
    if (outcome.committed) write(`Committed ${outcome.committed.sha.slice(0, 12)} on ${outcome.committed.branch}. Nothing was pushed.`);
    if (outcome.commitSkipped) write(outcome.credentialsFound ? style.bad(outcome.commitSkipped) : style.dim(outcome.commitSkipped));
    if (outcome.untracked) {
      write(
        style.warn(
          `Not included, because untracked files are never added automatically: ${outcome.untracked.slice(0, 10).join(", ")}${outcome.untracked.length > 10 ? ` and ${outcome.untracked.length - 10} more` : ""}. If one belongs to the fix, "git add" it and retest again.`
        )
      );
    }
    if (outcome.reportRefreshed) write(style.dim(`The local report now shows ${finding.id} as fixed. "${BRAND.cliName} report" opens it.`));
  } else if (retest.outcome === "needs_runtime_evidence") {
    write(`${style.warn("Needs runtime evidence")} ${finding.id} was proved against the running app, so it is closed the same way.`);
    write(`Repeat: ${finding.verificationPlan}`);
    write(`Then: ${BRAND.cliName} retest ${finding.id} --evidence "<request and response>"`);
  } else {
    write(`${style.bad("Still reproduces")} ${finding.id}. Keep working on the fix and retest again.`);
  }
  return outcome;
}
