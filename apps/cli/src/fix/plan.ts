import { BRAND } from "@myrqen/brand";
import type { Finding } from "@myrqen/contracts";
import { buildFixPrompt } from "@myrqen/report";
import type { DeterministicPlan } from "./deterministic.js";
import type { FixLoopRecord } from "./record.js";
import { needsRuntimeEvidence, staticRuleOf } from "./retest.js";

/**
 * The patch plan and the prompt the host agent works from.
 *
 * The plan is the contract between Myrqen and the agent for one finding: which
 * files to touch, what must be true afterwards, and the exact command that
 * decides whether it is. It never carries a source excerpt — the agent opens the
 * file itself, and a line read fresh from disk is a line nobody has redacted.
 */

export interface FixPlan {
  findingId: string;
  title: string;
  severity: string;
  verification: string;
  branch: string;
  baseBranch: string | null;
  mode: "deterministic" | "agent";
  /** Files the change is expected to touch, with the line the finding points at. */
  targets: string[];
  appliedEdits: string[];
  leftForAgent: string[];
  steps: string[];
  needsRuntimeEvidence: boolean;
  retestCommand: string;
  prompt: string;
}

function targets(finding: Finding, deterministic: DeterministicPlan | null): string[] {
  const list = new Set<string>();
  if (finding.affected.file) {
    list.add(`${finding.affected.file}${finding.affected.lineStart ? `:${finding.affected.lineStart}` : ""}`);
  }
  for (const edit of deterministic?.edits ?? []) {
    if (edit.file !== finding.affected.file) list.add(edit.file);
  }
  return [...list];
}

export function retestCommandFor(finding: Finding): string {
  return needsRuntimeEvidence(finding)
    ? `${BRAND.cliName} retest ${finding.id} --evidence "<the original request, repeated after the fix, and what came back>"`
    : `${BRAND.cliName} retest ${finding.id}`;
}

function loopInstructions(finding: Finding, record: FixLoopRecord, deterministic: DeterministicPlan | null): string[] {
  const runtime = needsRuntimeEvidence(finding);
  const rule = staticRuleOf(finding);
  const steps: string[] = [];
  if (record.mode === "deterministic") {
    steps.push(`${BRAND.displayName} already applied the mechanical part of this fix: ${(deterministic?.edits ?? []).map((edit) => edit.description).join("; ")}.`);
    if ((deterministic?.leftForAgent ?? []).length > 0) {
      steps.push(`Still for you: ${deterministic!.leftForAgent.join(" ")}`);
    }
    for (const followUp of deterministic?.followUp ?? []) steps.push(followUp);
  } else {
    steps.push(`Edit only what this finding needs, starting at ${targets(finding, deterministic).join(", ") || finding.affected.component}.`);
    steps.push(
      'Add the smallest regression test that fails before the change and passes after it, and run the project\'s tests for this area. A new file is only committed if you stage it with "git add <file>"; untracked files are never added for you.'
    );
  }
  if (runtime) {
    steps.push(
      `Repeat the request that proved this finding against the running app — ${finding.verificationPlan} — and note exactly what came back.`
    );
  }
  steps.push(
    runtime
      ? `Run \`${retestCommandFor(finding)}\`. Add --still-reproduces if the issue is still there.`
      : `Run \`${retestCommandFor(finding)}\`${rule ? ` (it re-runs rule ${rule} only)` : ""}.`
  );
  steps.push(
    `On a pass, ${BRAND.displayName} commits the change on ${record.branch} as "fix(security): ${finding.title} (${finding.id})" and marks the finding fixed and verified. It commits changes to tracked files and files you staged, lists untracked files instead of adding them, and refuses the commit if an added line looks like a credential. It never pushes and never touches ${record.baseBranch ?? "the branch you started on"}.`
  );
  steps.push(`On a fail, keep working on ${record.branch} and retest again. Do not commit by hand to make it pass.`);
  return steps;
}

export function buildFixPlan(finding: Finding, record: FixLoopRecord, deterministic: DeterministicPlan | null, context: { projectName: string }): FixPlan {
  const steps = loopInstructions(finding, record, deterministic);
  const base = buildFixPrompt(finding, { projectName: context.projectName, localReportId: record.localReportId });
  // The shared prompt ends with a generic "after the change" section; in the fix
  // loop the retest command replaces it, so the agent has one instruction, not two.
  const cut = base.indexOf("## After the change");
  const head = (cut === -1 ? base : base.slice(0, cut)).trimEnd();
  const prompt = [
    head,
    "",
    `## ${BRAND.displayName} fix loop`,
    `You are on branch ${record.branch}, created from ${record.baseBranch ?? "a detached HEAD"} for this finding alone.`,
    ...steps.map((step, index) => `${index + 1}. ${step}`),
    "",
    "Never mark this finding fixed yourself, and never put a secret value in code, tests, evidence, or the commit."
  ].join("\n");

  return {
    findingId: finding.id,
    title: finding.title,
    severity: finding.severity,
    verification: finding.verification,
    branch: record.branch,
    baseBranch: record.baseBranch,
    mode: record.mode,
    targets: targets(finding, deterministic),
    appliedEdits: record.mode === "deterministic" ? (deterministic?.edits ?? []).map((edit) => `${edit.file}: ${edit.description}`) : [],
    leftForAgent: deterministic?.leftForAgent ?? [],
    steps,
    needsRuntimeEvidence: needsRuntimeEvidence(finding),
    retestCommand: retestCommandFor(finding),
    prompt
  };
}
