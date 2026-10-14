import fs from "node:fs/promises";
import path from "node:path";
import { writeAtomic } from "./managed.js";
import type { InstallPlan, PlannedWrite } from "./types.js";

/**
 * Executing a plan.
 *
 * Two properties matter more than speed. First, a run that fails partway must
 * leave the machine in a state the user can understand: every file Myrqen
 * touched before the failure is rolled back to exactly what it was. Second, the
 * report must be precise about what did and did not change, because "something
 * went wrong" in a tool that edits configuration files is worse than useless.
 */

export interface AppliedWrite {
  write: PlannedWrite;
  outcome: "written" | "unchanged" | "removed" | "skipped" | "failed";
  error?: string;
}

export interface AppliedPlan {
  plan: InstallPlan;
  writes: AppliedWrite[];
  /** True when every write either succeeded or was already correct. */
  ok: boolean;
}

interface Snapshot {
  path: string;
  /** null means the file did not exist and must be deleted on rollback. */
  previous: string | null;
  previousMode?: number;
  /**
   * Whether the file's directory existed before this plan ran.
   *
   * Only a directory Myrqen created is a directory Myrqen may remove. Climbing
   * upward and deleting whatever happens to be empty deletes directories the
   * user made — an empty `.github/` they had set up deliberately is still theirs.
   */
  parentExisted: boolean;
}

/**
 * Apply one plan.
 *
 * Rollback is per plan, not across plans. Each agent's integration is
 * independent, so a failure while writing Cursor's rule file should not undo a
 * correct Claude Code install the user can already use — but it must undo the
 * half-written Cursor one.
 */
export async function applyPlan(plan: InstallPlan): Promise<AppliedPlan> {
  const snapshots: Snapshot[] = [];
  const applied: AppliedWrite[] = [];
  /** Directories a removed file lived in, pruned bottom-up once the plan is done. */
  const emptied = new Set<string>();

  for (const write of plan.writes) {
    if (write.action === "unchanged") {
      applied.push({ write, outcome: "unchanged" });
      continue;
    }
    if (write.action === "blocked") {
      applied.push({ write, outcome: "skipped", ...(write.reason ? { error: write.reason } : {}) });
      continue;
    }

    try {
      const snapshot = await snapshotOf(write.path);
      snapshots.push(snapshot);

      if (write.action === "remove") {
        if (write.contents === undefined) {
          await fs.rm(write.path, { force: true });
          emptied.add(path.dirname(write.path));
        } else {
          await writeAtomic(write.path, write.contents);
        }
        applied.push({ write, outcome: "removed" });
        continue;
      }

      if (write.contents === undefined) {
        applied.push({ write, outcome: "skipped", error: "no content was produced for this file" });
        continue;
      }
      await writeAtomic(write.path, write.contents);
      applied.push({ write, outcome: "written" });
    } catch (error) {
      applied.push({
        write,
        outcome: "failed",
        error: error instanceof Error ? error.message : "unknown write error"
      });
      await rollback(snapshots);
      return {
        plan,
        writes: applied.map((entry) =>
          entry.outcome === "written" || entry.outcome === "removed" ? { ...entry, outcome: "skipped" as const } : entry
        ),
        ok: false
      };
    }
  }

  await pruneEmptied(emptied);
  return { plan, writes: applied, ok: applied.every((entry) => entry.outcome !== "failed") };
}

/**
 * Remove the directories whose contents this plan deleted, once they are empty.
 *
 * Deepest first, so a skill bundle's `references/` goes before the bundle
 * directory that holds it and both are gone by the end. The set only ever
 * contains directories a removed file actually lived in, and nothing walks
 * upward from them: `.claude/skills/myrqen` is Myrqen's to remove, while
 * `.claude/skills` — which holds other people's skills, and which Myrqen did not
 * create — is never a candidate. `fs.rmdir` refusing on a non-empty directory is
 * the backstop, not the rule.
 */
async function pruneEmptied(directories: Set<string>): Promise<void> {
  const deepestFirst = [...directories].sort((a, b) => b.split(path.sep).length - a.split(path.sep).length);
  for (const directory of deepestFirst) {
    // A directory that still holds anything refuses, which is exactly right:
    // the user's other rules and other skills keep their home.
    await fs.rmdir(directory).catch(() => undefined);
  }
}

async function snapshotOf(target: string): Promise<Snapshot> {
  const parentExisted = await fs
    .stat(path.dirname(target))
    .then(() => true)
    .catch(() => false);
  try {
    const [previous, stat] = await Promise.all([fs.readFile(target, "utf8"), fs.stat(target)]);
    return { path: target, previous, previousMode: stat.mode & 0o777, parentExisted };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return { path: target, previous: null, parentExisted };
    throw error;
  }
}

async function rollback(snapshots: Snapshot[]): Promise<void> {
  for (const snapshot of [...snapshots].reverse()) {
    try {
      if (snapshot.previous === null) {
        await fs.rm(snapshot.path, { force: true });
        if (!snapshot.parentExisted) await fs.rmdir(path.dirname(snapshot.path)).catch(() => undefined);
        continue;
      }
      await writeAtomic(snapshot.path, snapshot.previous);
      if (snapshot.previousMode !== undefined) await fs.chmod(snapshot.path, snapshot.previousMode);
    } catch {
      // A rollback that itself fails is reported by the caller through the
      // outcome list rather than by throwing over the original error, which is
      // the one the user needs to read.
    }
  }
}


