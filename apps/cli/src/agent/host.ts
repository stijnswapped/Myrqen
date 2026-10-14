import { BRAND } from "@myrqen/brand";
import { adapterContext } from "../integrations/context.js";
import { detectAll } from "../integrations/registry.js";

/**
 * Is a coding agent driving this run?
 *
 * Verification is the agent's job: Myrqen has no model of its own, so a run
 * started from a plain terminal stops after the static pass with every candidate
 * unproven. That is correct behaviour and a terrible first impression unless the
 * CLI says so — plainly, at the start and at the end, and with the exact words
 * that would continue the run in an agent this machine actually has.
 *
 * Detection reads environment variables the hosts set for the shells they spawn.
 * Nothing is executed and nothing is read from disk here. A host we cannot
 * recognise is reported as "not detected", never guessed.
 */

export interface HostAgentSignal {
  detected: boolean;
  /** A stable display name, when one is known. */
  name?: string;
  source?: "flag" | "environment";
}

/**
 * Markers each host sets in the shells it spawns, cross-checked against the
 * `is-ai-agent` crate's registry (docs.rs, 0.4.0) and vendor issue trackers.
 * Order matters: Amp sets CLAUDECODE for compatibility and Qwen Code is a
 * Gemini CLI fork, so their own markers are read first.
 */
const present = (value: string | undefined): boolean => value !== undefined && value !== "" && value !== "0";

const ENV_SIGNALS: ReadonlyArray<{ name: string; test: (env: NodeJS.ProcessEnv) => boolean }> = [
  { name: "Amp", test: (env) => present(env.AMP_CURRENT_THREAD_ID) },
  {
    name: "Claude Code",
    test: (env) => present(env.CLAUDECODE) || present(env.CLAUDE_CODE_ENTRYPOINT) || present(env.CLAUDE_CODE_SESSION_ID)
  },
  {
    name: "Codex",
    test: (env) =>
      present(env.CODEX_THREAD_ID) || present(env.CODEX_SANDBOX) || present(env.CODEX_SANDBOX_NETWORK_DISABLED) || present(env.CODEX_CI)
  },
  { name: "OpenCode", test: (env) => present(env.OPENCODE) || present(env.OPENCODE_PID) || present(env.OPENCODE_CLIENT) },
  { name: "Qwen Code", test: (env) => present(env.QWEN_CODE) },
  { name: "Gemini CLI", test: (env) => present(env.GEMINI_CLI) },
  {
    name: "Cursor",
    test: (env) => present(env.CURSOR_AGENT) || present(env.CURSOR_SANDBOX) || env.CURSOR_EXTENSION_HOST_ROLE === "agent-exec"
  },
  { name: "GitHub Copilot", test: (env) => present(env.COPILOT_AGENT_SESSION_ID) },
  { name: "Cline", test: (env) => present(env.CLINE_ACTIVE) },
  { name: "Roo Code", test: (env) => present(env.ROO_ACTIVE) }
];

const AI_AGENT_NAMES: ReadonlyArray<[RegExp, string]> = [
  [/^claude[-_]?code/i, "Claude Code"],
  [/^codex/i, "Codex"],
  [/^opencode/i, "OpenCode"],
  [/^gemini/i, "Gemini CLI"],
  [/^cursor/i, "Cursor"],
  [/^amp/i, "Amp"],
  [/^goose/i, "Goose"]
];

export function detectHostAgent(env: NodeJS.ProcessEnv = process.env, explicitName?: string): HostAgentSignal {
  const named = explicitName?.trim();
  if (named && named.toLowerCase() !== "unknown") return { detected: true, name: named, source: "flag" };

  for (const signal of ENV_SIGNALS) {
    if (signal.test(env)) return { detected: true, name: signal.name, source: "environment" };
  }
  // `AI_AGENT` is a cross-vendor convention: "<agent>_<version>_<mode>".
  const generic = env.AI_AGENT?.trim();
  if (generic) {
    const match = AI_AGENT_NAMES.find(([pattern]) => pattern.test(generic));
    return { detected: true, name: match ? match[1] : generic.split("_")[0]!.slice(0, 60), source: "environment" };
  }
  return { detected: false };
}

/** How to hand the run to each agent Myrqen integrates with, in its own syntax. */
const HINTS: Readonly<Record<string, (effort: string) => string>> = {
  "claude-code": (effort) => `/${BRAND.skillId} ${effort} inside Claude Code`,
  codex: (effort) => `$${BRAND.skillId} ${effort} in a Codex session`,
  opencode: (effort) => `ask OpenCode to run "${BRAND.cliName} ${effort}"`,
  cursor: (effort) => `/${BRAND.skillId} ${effort} in the Cursor agent`,
  kiro: (effort) => `/${BRAND.skillId} ${effort} in Kiro`,
  "gemini-cli": (effort) => `ask Gemini CLI to run "${BRAND.cliName} ${effort}"`,
  "github-copilot": (effort) => `ask GitHub Copilot's agent to run "${BRAND.cliName} ${effort}"`,
  windsurf: (effort) => `ask Windsurf's Cascade to run "${BRAND.cliName} ${effort}"`,
  cline: (effort) => `ask Cline to run "${BRAND.cliName} ${effort}"`,
  "roo-code": (effort) => `ask Roo Code to run "${BRAND.cliName} ${effort}"`,
  continue: (effort) => `ask Continue to run "${BRAND.cliName} ${effort}"`,
  aider: (effort) => `ask Aider to run "${BRAND.cliName} ${effort}"`
};

const FALLBACK_ORDER = ["claude-code", "codex", "opencode"];

/**
 * Hints for the agents detected on this machine, most capable first. With none
 * detected, the three launch hosts are named so the sentence is still useful.
 */
export function verificationHints(installedAgentIds: readonly string[], effort = "auto"): string[] {
  const known = installedAgentIds.filter((id) => HINTS[id]);
  const ids = known.length > 0 ? known : FALLBACK_ORDER;
  return ids.slice(0, 3).map((id) => HINTS[id]!(effort));
}

/** Detected agents, from the filesystem only. Never throws, never executes. */
export async function installedAgentIds(repoRoot: string): Promise<string[]> {
  try {
    const context = await adapterContext(repoRoot);
    const detected = await detectAll(context);
    return detected.filter((entry) => entry.detection.detected).map((entry) => entry.adapter.id);
  } catch {
    return [];
  }
}

export function joinHints(hints: readonly string[]): string {
  if (hints.length <= 1) return hints[0] ?? "";
  return `${hints.slice(0, -1).join(", ")}, or ${hints[hints.length - 1]}`;
}

/** The start-of-run line for a terminal with no agent behind it. */
export function staticOnlyIntro(): string {
  return `No coding agent detected. ${BRAND.displayName} will run its static pass only; proving each candidate against your running app is your agent's job.`;
}

/** The end-of-run sentence: what is unproven, and the exact way to prove it. */
export function staticOnlySummary(unproven: number, hints: readonly string[]): string {
  const subject =
    unproven === 0
      ? "Static pass only — nothing to prove yet, but runtime checks were not run."
      : `Static pass only — ${unproven} finding${unproven === 1 ? " needs" : "s need"} proof.`;
  return `${subject} Run ${joinHints(hints)} to verify ${unproven === 1 ? "it" : "them"}.`;
}
