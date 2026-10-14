/**
 * The agent-integration layer.
 *
 * Two very different things in this product are called "detection", and keeping
 * them apart is a deliberate architectural decision:
 *
 *   - *Security detection* finds vulnerabilities in application code. It lives
 *     in `@myrqen/scan` and in the host agent's own reasoning.
 *   - *Environment detection*, in this directory, finds coding agents installed
 *     on this machine and works out where Myrqen may safely integrate.
 *
 * Nothing here reads application source, and nothing in the scanner reads a
 * user's editor configuration. They share no vocabulary, no metrics, and no
 * log lines.
 */

/** Where an integration lives. */
export type Scope = "project" | "global";

/**
 * How sure we are that this agent is actually installed.
 *
 * A directory with the right name is not proof. The distinction exists so the
 * installer can default to the agents it is sure about while still letting a
 * user pick one it only suspects.
 */
export type DetectionConfidence =
  /** More than one independent signal, or an executable sitting on `PATH`. */
  | "confirmed"
  /** One credible signal, such as a documented configuration directory. */
  | "probable"
  /** Only a Myrqen integration file in this project; the agent itself was not seen. */
  | "project_only"
  /** Nothing was found. */
  | "absent";

/** A single, independently meaningful reason to believe an agent is installed. */
export interface DetectionSignal {
  kind:
    | "executable"
    | "application"
    | "extension"
    | "config_directory"
    | "config_file"
    | "project_config"
    | "package_manager"
    | "environment_variable";
  /**
   * What was found, safe to print. Paths under the user's home are abbreviated
   * to `~/…` and no file *contents* ever appear here.
   */
  detail: string;
}

export interface DetectionResult {
  detected: boolean;
  confidence: DetectionConfidence;
  signals: DetectionSignal[];
  /**
   * A nicety printed beside the row, never evidence.
   *
   * Absent whenever this run declined to execute anything, which is the default
   * outside an attended terminal. Nothing may branch on it: `confidence` is
   * reached entirely from `signals`, every one of which is established by
   * reading the filesystem.
   */
  version?: string;
}

/**
 * One third-party command Myrqen is willing to execute, named by the adapter
 * that owns it.
 *
 * Nothing is executed that is not described here. The declaration is a claim
 * about a specific program — "this flag prints and exits" — and it is made in
 * the adapter file, next to the documentation link that supports it, because
 * that is where a maintainer will be when they learn the claim has stopped
 * being true.
 */
export interface CommandProbe {
  /** The executable's name as it appears on PATH, used for the ledger line. */
  command: string;
  /** The single argument passed. Documented to print something and exit. */
  flag: string;
  /**
   * Set to opt out, with the reason.
   *
   * An adapter says "do not execute this one" when the CLI does more than print
   * on launch. GitHub Copilot's CLI bootstraps itself the first time it runs —
   * hundreds of files and hundreds of megabytes into the home directory — so it
   * carries a reason here and is never executed, whatever the flags say.
   */
  never?: string;
}

/** Whether this run may execute a third-party CLI, and the one clause that says why. */
export interface ProbeDecision {
  allowed: boolean;
  /** Printed by `--dry-run` and `doctor`, so the default is never a mystery. */
  reason: string;
}

/**
 * The record of what detection actually executed.
 *
 * `--dry-run` promises that nothing was written *by Myrqen*. That promise is
 * only honest if the same output also names the programs Myrqen launched, since
 * what those do afterwards is their own business and not something a dry run
 * can undo.
 */
export interface ProbeLedger {
  decision: ProbeDecision;
  /** Appends one command line. Called before the spawn, never after. */
  record(commandLine: string): void;
  /** Every command line executed in this run, first seen first, deduplicated. */
  executed(): string[];
}

/** What a plan step will do to one file. */
export type FileAction =
  /** The file does not exist and will be written. */
  | "create"
  /** A Myrqen-managed region exists and its content changes. */
  | "update"
  /** The file exists with content Myrqen does not own; only a managed region is added. */
  | "merge"
  /** Already exactly right. */
  | "unchanged"
  /** A Myrqen-managed region or file is removed. */
  | "remove"
  /** Cannot be done safely; `reason` says why. */
  | "blocked";

export interface PlannedWrite {
  /** Absolute path on this machine. */
  path: string;
  /** Shown to the user: relative to the project, or `~/…` for a global target. */
  displayPath: string;
  action: FileAction;
  /** The complete file content after the change. Absent for `unchanged` and `blocked`. */
  contents?: string;
  /** True when the file contains content Myrqen did not write and must preserve. */
  preservesExistingContent: boolean;
  /** Present when `action` is `blocked`. */
  reason?: string;
}

export interface InstallPlan {
  adapterId: string;
  displayName: string;
  scope: Scope;
  writes: PlannedWrite[];
  /** Shown under the plan, for example "Invoke with /myrqen auto". */
  notes: string[];
}

/** What Myrqen believes is installed for one agent, reconstructed from disk. */
export interface InstalledIntegration {
  adapterId: string;
  scope: Scope;
  /** Absolute path of the managed file. */
  path: string;
  displayPath: string;
  /** The payload revision that file carries. */
  payloadVersion: string;
  /** True when the file also holds content Myrqen does not own. */
  sharedFile: boolean;
}

export type IntegrationHealth = "healthy" | "stale" | "conflicted" | "missing";

export interface ValidationResult {
  health: IntegrationHealth;
  detail: string;
  /** A command the user can run to put it right. */
  remedy?: string;
}

/**
 * The integration primitive an adapter writes.
 *
 * Choosing the right one per agent is the difference between a useful product
 * and thousands of tokens of always-on instructions in every conversation. An
 * agent that supports on-demand skills gets a skill; one that only reads a
 * persistent instruction file gets a short pointer, never the whole method.
 */
export type IntegrationPrimitive =
  | "skill"
  | "command"
  | "rules_file"
  | "instructions_file"
  | "managed_section";

export interface AdapterContext {
  /** Repository root of the project being linked, already resolved. */
  repoRoot: string;
  /** The user's home directory, injected so tests can supply a fixture. */
  home: string;
  /** Directory holding the portable skill bundle that ships with this CLI. */
  skillSource: string;
  /** Platform, injected so a Windows path test can run on any machine. */
  platform: NodeJS.Platform;
  env: NodeJS.ProcessEnv;
  /**
   * Whether this run may execute a third-party CLI, and the record of what it
   * did execute.
   *
   * Optional, and its absence means "execute nothing". Code that never
   * considered the question — a fixture context in a test, a command that only
   * reads files — must not be able to launch somebody's agent CLI by accident,
   * so the safe answer is the one you get for free.
   */
  probe?: ProbeLedger;
}

export interface AgentAdapter {
  /** Stable machine identifier used by `--agent`, config, and JSON output. */
  id: string;
  displayName: string;
  /** Where the integration format is documented, recorded so a future maintainer can check it. */
  documentation: string;
  /** The native integration this adapter writes. */
  primitive: IntegrationPrimitive;
  /** Platforms the agent itself runs on. */
  platforms: readonly NodeJS.Platform[];
  /**
   * Every command this adapter is willing to execute, and the ones it refuses.
   *
   * Declared here as well as used inside `detect()` so the whole set is
   * inspectable from one place: a test asserts that no adapter executes anything
   * it has not declared, and that an opted-out CLI stays opted out.
   */
  readonly probes?: readonly CommandProbe[];

  detect(context: AdapterContext): Promise<DetectionResult>;
  supportedScopes(context: AdapterContext): Scope[];
  createInstallPlan(context: AdapterContext, scope: Scope): Promise<InstallPlan>;
  /** Reconstructed from managed markers on disk, never from a central database. */
  installed(context: AdapterContext): Promise<InstalledIntegration[]>;
  validate(context: AdapterContext, integration: InstalledIntegration): Promise<ValidationResult>;
  createUninstallPlan(context: AdapterContext, scope: Scope): Promise<InstallPlan>;
}
