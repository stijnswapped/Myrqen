import { BRAND } from "@myrqen/brand";
import { blank, bullet, capabilityNote, style, write } from "../ui/output.js";
import type { AppliedPlan } from "./apply.js";
import type { FileAction, InstallPlan, PlannedWrite } from "./types.js";

/**
 * Showing the user what will change, before it changes.
 *
 * A tool that edits files in a developer's home directory has to earn that. The
 * plan is printed in full, every action is named with the same word every time,
 * and a file that already holds the user's own content says so on its own line —
 * because "MERGE — existing instructions preserved" is the sentence that decides
 * whether someone types y.
 */

const ACTION_LABEL: Record<FileAction, string> = {
  create: "CREATE ",
  update: "UPDATE ",
  merge: "MERGE  ",
  unchanged: "OK     ",
  remove: "REMOVE ",
  blocked: "BLOCKED"
};

function paintAction(action: FileAction): string {
  const label = ACTION_LABEL[action];
  if (action === "blocked") return style.bad(label);
  if (action === "unchanged") return style.dim(label);
  if (action === "remove") return style.warn(label);
  return style.ok(label);
}

export function planIsNoop(plan: InstallPlan): boolean {
  return plan.writes.every((write_) => write_.action === "unchanged");
}

export function planTouchesUserContent(plan: InstallPlan): boolean {
  return plan.writes.some((write_) => write_.preservesExistingContent && write_.action !== "unchanged");
}

/**
 * Collapse a directory that is being written as a unit.
 *
 * A skill bundle is six files, and printing six lines for it buries the one line
 * that matters — the `CLAUDE.md` the user already has content in. Files that
 * share a parent directory, carry the same action, and are all Myrqen's own are
 * shown as the directory plus a count. `--verbose` prints every path.
 */
function collapse(writes: PlannedWrite[], verbose: boolean): Array<{ line: PlannedWrite; extra?: number }> {
  if (verbose) return writes.map((line) => ({ line }));

  const groups = new Map<string, PlannedWrite[]>();
  const order: string[] = [];
  for (const entry of writes) {
    const directory = entry.displayPath.includes("/")
      ? entry.displayPath.slice(0, entry.displayPath.lastIndexOf("/"))
      : "";
    const key = `${directory}::${entry.action}::${entry.preservesExistingContent}`;
    if (!groups.has(key)) {
      groups.set(key, []);
      order.push(key);
    }
    groups.get(key)!.push(entry);
  }

  const rendered: Array<{ line: PlannedWrite; extra?: number }> = [];
  for (const key of order) {
    const group = groups.get(key)!;
    const directory = key.slice(0, key.indexOf("::"));
    if (group.length < 3 || directory === "" || group[0]!.preservesExistingContent) {
      for (const entry of group) rendered.push({ line: entry });
      continue;
    }
    rendered.push({
      line: { ...group[0]!, displayPath: `${directory}/` },
      extra: group.length
    });
  }
  return rendered;
}

export function renderPlans(plans: InstallPlan[], options: { verbose?: boolean } = {}): void {
  for (const plan of plans) {
    const scope = plan.scope === "project" ? "this project" : "global";
    write(`${style.bold(plan.displayName)} ${style.dim(`· ${scope}`)}`);
    for (const { line, extra } of collapse(plan.writes, options.verbose === true)) {
      const suffix =
        line.action === "merge"
          ? style.dim("  existing content preserved")
          : line.action === "blocked"
            ? style.dim(`  ${line.reason ?? "not possible on this machine"}`)
            : extra
              ? style.dim(`  ${extra} files`)
              : "";
      write(`  ${paintAction(line.action)} ${line.displayPath}${suffix}`);
    }
    for (const note of plan.notes) capabilityNote(`  ${note}`);
    blank();
  }
}

/**
 * One line the user reads before answering yes or no.
 *
 * Every clause is counted from the plan. An earlier version ended with a
 * reassuring constant — "no existing instructions are removed" — that was true
 * of the plans it happened to be tested on and was printed regardless. In a tool
 * whose central promise is that it does not clobber configuration, a comforting
 * sentence that is not a measurement is worse than no sentence at all.
 */
export function planSummaryLine(plans: InstallPlan[]): string {
  const changing = plans
    .flatMap((plan) => plan.writes)
    .filter((write_) => write_.action !== "unchanged" && write_.action !== "blocked");
  const merging = changing.filter((write_) => write_.preservesExistingContent);
  const removing = changing.filter((write_) => write_.action === "remove");
  const blocked = plans.flatMap((plan) => plan.writes).filter((write_) => write_.action === "blocked");

  const parts = [`${changing.length} file(s) will change`];
  if (merging.length > 0) {
    parts.push(`${merging.length} of them already hold content of yours, which is kept`);
  }
  if (removing.length > 0) parts.push(`${removing.length} lose a ${BRAND.displayName} section`);
  if (blocked.length > 0) parts.push(`${blocked.length} cannot be written and are skipped`);
  return `${parts.join(", ")}.`;
}

export function renderApplied(results: AppliedPlan[]): void {
  let written = 0;
  let unchanged = 0;
  let removed = 0;
  const failures: string[] = [];

  for (const result of results) {
    const lines = result.writes.filter((entry) => entry.outcome !== "unchanged");
    if (lines.length === 0 && result.writes.length > 0) {
      write(`${style.dim("·")} ${result.plan.displayName} ${style.dim("up to date")}`);
      unchanged += result.writes.length;
      continue;
    }
    write(style.bold(result.plan.displayName));
    const collapsedWritten = collapse(
      result.writes.filter((entry) => entry.outcome === "written").map((entry) => entry.write),
      false
    );
    for (const { line, extra } of collapsedWritten) {
      written += extra ?? 1;
      write(`  ${style.ok("✓")} ${line.displayPath}${extra ? style.dim(`  ${extra} files`) : ""}`);
    }
    for (const entry of result.writes) {
      if (entry.outcome === "written") {
        continue;
      } else if (entry.outcome === "removed") {
        removed += 1;
        write(`  ${style.ok("✓")} removed from ${entry.write.displayPath}`);
      } else if (entry.outcome === "unchanged") {
        unchanged += 1;
        write(`  ${style.dim("·")} ${entry.write.displayPath} ${style.dim("already current")}`);
      } else {
        failures.push(`${result.plan.displayName}: ${entry.write.displayPath} — ${entry.error ?? "not applied"}`);
        write(`  ${style.bad("×")} ${entry.write.displayPath} ${style.dim(entry.error ?? "")}`);
      }
    }
    for (const note of result.plan.notes) capabilityNote(`  ${note}`);
    blank();
  }

  const installed = results.filter((result) => result.ok && result.writes.some((entry) => entry.outcome === "written")).length;
  // Counted, not asserted. The only honest thing to say about the user's own
  // content is how many of the files touched had some and kept it.
  const preserved = results
    .flatMap((result) => result.writes)
    .filter(
      (entry) =>
        (entry.outcome === "written" || entry.outcome === "removed") && entry.write.preservesExistingContent
    ).length;
  write(
    `${installed} integration(s) installed · ${written} file(s) written · ${unchanged} already current${
      removed > 0 ? ` · ${removed} removed` : ""
    }`
  );
  if (preserved > 0) {
    write(`${preserved} file(s) already had content of your own, and still do`);
  }

  if (failures.length > 0) {
    blank();
    write(style.bold("Not applied"));
    for (const failure of failures) bullet(failure);
    capabilityNote(
      `Everything above that shows ✓ is installed and usable. Run "${BRAND.cliName} doctor" for what to do about the rest.`
    );
  }
}
