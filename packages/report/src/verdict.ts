import type { Finding, Severity, Verification } from "@myrqen/contracts";
import { buildQuickFixPrompt, findingLocation, type FixPromptContext } from "./fix-prompt.js";
import { isSettled, reportFacts, sortFindings, type RunMode, type SummarizableFacts } from "./facts.js";

/**
 * The report's first sentence, and the three things to do about it.
 *
 * A reader opening a security report wants one answer before anything else: is
 * there something I have to fix, and how sure is this? The verdict answers that from
 * the same counts every other section prints, then names at most three findings to
 * start with and hands over a prompt for each. Everything else in the report is the
 * argument for this paragraph.
 *
 * The verdict is recomputed from whatever the renderer is given. A stored verdict on a
 * canonical report is a convenience for machine consumers; a projection never carries
 * one, and a renderer never trusts one, because a verdict written for the full report
 * can name a finding the current viewer is not allowed to see.
 */

export type VerdictTone = "verified_risk" | "unverified_risk" | "clear" | "settled" | "withheld";

export interface VerdictItem {
  findingId: string;
  title: string;
  severity: Severity;
  verification: Verification;
  /** `file:line`, or the origin or component when no file is recorded. */
  location: string;
  route?: string;
  /** One line on why this one matters, taken from the finding's own impact. */
  why: string;
  /** A short, paste-ready prompt for the reader's coding agent. */
  fixPrompt: string;
}

export interface ReportVerdict {
  tone: VerdictTone;
  /** One line. */
  headline: string;
  /** The counts behind the headline, as one sentence, or null when there are none. */
  detail: string | null;
  runMode: RunMode;
  /** What to do next when the report cannot say more on its own. */
  nextStep: string | null;
  fixFirst: VerdictItem[];
  /** Printed with every verdict, whatever it says. */
  caveat: string;
}

export const VERDICT_CAVEAT =
  "A clean report is not evidence that an application is secure: it says only what these checks, over this scope, did and did not find.";

const RUN_IN_AGENT =
  "Run /myrqen inside your coding agent (Claude Code, Codex, Cursor, or another) so it can confirm or refute each finding against the running app.";

const SEVERITY_WEIGHT: Record<Severity, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

/**
 * Proof discounts severity rather than replacing it. A verified high outranks a
 * critical on strong evidence, because one has been observed and the other has not;
 * a critical that still needs review sits below a medium on strong evidence, because
 * an unreviewed claim is the least certain thing in the report.
 */
const VERIFICATION_WEIGHT: Record<Verification, number> = { verified: 1, strong_evidence: 0.75, needs_review: 0.4 };

export function priorityScore(finding: Pick<Finding, "severity" | "verification">): number {
  return SEVERITY_WEIGHT[finding.severity] * VERIFICATION_WEIGHT[finding.verification];
}

export const FIX_FIRST_LIMIT = 3;

/** Open findings, most urgent first, ties broken by the report's own order. */
export function rankForFixing(findings: readonly Finding[]): Finding[] {
  const ordered = sortFindings(findings.filter((finding) => !isSettled(finding)));
  const position = new Map(ordered.map((finding, index) => [finding.id, index]));
  return [...ordered].sort(
    (a, b) => priorityScore(b) - priorityScore(a) || position.get(a.id)! - position.get(b.id)!
  );
}

const WHY_LIMIT = 180;

/** The first sentence of the impact, cut on a word boundary if it runs long. */
export function oneLine(text: string): string {
  const flat = text.replace(/\s+/g, " ").trim();
  const sentence = /^(.+?[.!?])(\s|$)/.exec(flat)?.[1] ?? flat;
  if (sentence.length <= WHY_LIMIT) return sentence;
  const cut = sentence.slice(0, WHY_LIMIT);
  return `${cut.slice(0, Math.max(cut.lastIndexOf(" "), WHY_LIMIT - 30)).replace(/[,;:\s]+$/, "")}…`;
}

function plural(count: number, singular: string, pluralForm = `${singular}s`): string {
  return count === 1 ? singular : pluralForm;
}

function severityPhrase(counts: Record<Severity, number>): string {
  const parts = (["critical", "high", "medium", "low", "info"] as const)
    .filter((severity) => counts[severity] > 0)
    .map((severity) => `${counts[severity]} ${severity}`);
  return parts.join(", ");
}

function verificationPhrase(counts: Record<Verification, number>): string {
  return `${counts.verified} verified, ${counts.strong_evidence} on strong evidence, ${counts.needs_review} ${plural(counts.needs_review, "needs", "need")} review`;
}

function item(finding: Finding, context: FixPromptContext): VerdictItem {
  const out: VerdictItem = {
    findingId: finding.id,
    title: finding.title,
    severity: finding.severity,
    verification: finding.verification,
    location: findingLocation(finding),
    why: oneLine(finding.impact),
    fixPrompt: buildQuickFixPrompt(finding, context)
  };
  if (finding.affected.route) out.route = finding.affected.route;
  return out;
}

export function buildVerdict(report: SummarizableFacts & { id?: string; project?: { name: string } }): ReportVerdict {
  const facts = reportFacts(report);
  const runMode = facts.run.mode;
  const staticOnly = runMode === "static_only";
  const base = { runMode, caveat: VERDICT_CAVEAT };

  if (!Array.isArray(report.findings)) {
    return {
      ...base,
      tone: "withheld",
      headline: "This view does not include the findings, so it carries no verdict.",
      detail: facts.counts
        ? `The report records ${facts.counts.total} ${plural(facts.counts.total, "finding")}: ${verificationPhrase(facts.counts.verification)}.`
        : null,
      nextStep: null,
      fixFirst: []
    };
  }

  const counts = facts.counts!;
  const context: FixPromptContext = staticOnly ? { staticOnly: true } : {};
  if (report.project?.name) context.projectName = report.project.name;
  if (report.id) context.localReportId = report.id;
  const fixFirst = rankForFixing(report.findings).slice(0, FIX_FIRST_LIMIT).map((finding) => item(finding, context));

  if (counts.total === 0) {
    return {
      ...base,
      tone: "clear",
      headline: staticOnly
        ? "No findings from a static pass — and no agent drove this run, so nothing was checked against the running app."
        : "No findings in the scope this scan covered.",
      detail: null,
      nextStep: staticOnly ? RUN_IN_AGENT : "Read the coverage and limitations to see what that scope was.",
      fixFirst
    };
  }

  if (counts.open === 0) {
    return {
      ...base,
      tone: "settled",
      headline: `Nothing left open: all ${counts.total} ${plural(counts.total, "finding is", "findings are")} fixed and verified, accepted, or refuted.`,
      detail: `${counts.fixed} fixed and verified.`,
      nextStep: null,
      fixFirst
    };
  }

  const settledNote = counts.open < counts.total ? ` (${counts.total - counts.open} more already closed out)` : "";
  const detail = `${counts.open} open ${plural(counts.open, "finding")}${settledNote}. Severity: ${severityPhrase(counts.severity)}. Verification: ${verificationPhrase(counts.verification)}.`;

  if (counts.openVerified > 0) {
    const worst = rankForFixing(report.findings).find((finding) => finding.verification === "verified")!;
    const severe = worst.severity === "critical" || worst.severity === "high";
    return {
      ...base,
      tone: "verified_risk",
      headline: `${counts.openVerified} verified ${plural(counts.openVerified, "vulnerability", "vulnerabilities")}${
        severe ? `, the worst ${worst.severity}` : ""
      } — fix ${counts.openVerified === 1 ? "it" : "these"} before you ship.`,
      detail,
      nextStep: "Paste each prompt below into your coding agent, and record a fix only after its own check passes.",
      fixFirst
    };
  }

  return {
    ...base,
    tone: "unverified_risk",
    headline: staticOnly
      ? `${counts.open} possible ${plural(counts.open, "vulnerability", "vulnerabilities")} from a static pass — none verified, because no agent drove this run.`
      : `${counts.open} open ${plural(counts.open, "finding")}, none verified yet.`,
    detail,
    nextStep: staticOnly
      ? RUN_IN_AGENT
      : "Start the app locally and run /myrqen again so your agent can confirm or refute these, beginning with the ones below.",
    fixFirst
  };
}
