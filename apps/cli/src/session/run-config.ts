import { BRAND } from "@myrqen/brand";
import {
  isValidEnvName,
  makeRunConfig,
  readProjectConfig,
  writeProjectConfig,
  type ProjectRunConfig
} from "../config/project-config.js";
import { isRunConfigTrusted, trustRunConfig } from "../config/run-trust.js";
import { detectRunConfig, type RunConfig } from "../discovery/runtime.js";
import { confirm, isInteractive, text } from "../ui/prompt.js";
import { capabilityNote, field, write } from "../ui/output.js";

export interface RunConfigFlags {
  startCommand?: string;
  /** A port or a loopback URL. */
  appUrl?: string;
  env?: string[];
}

export interface ResolvedRunConfig {
  run: ProjectRunConfig | null;
  persisted: boolean;
  /**
   * True only when this machine wrote the run settings or the user confirmed
   * them here. A committed config from the repository is unconfirmed until then,
   * and its start command must not be run without asking the user.
   */
  confirmed: boolean;
  /** The user was shown the committed start command and said no. */
  declined?: boolean;
  /** True when this call asked the user a question. */
  asked: boolean;
}

/** A detected proposal, held to the same rules as a saved one; null when it does not pass them. */
function fromDetected(detected: RunConfig): ProjectRunConfig | null {
  try {
    return makeRunConfig(
      { command: detected.command, target: detected.port, env: detected.env.filter((name) => isValidEnvName(name)) },
      "detected"
    );
  } catch {
    return null;
  }
}

/**
 * The run configuration for this scan, asked for at most once per project.
 *
 * Order: explicit flags (persisted, for non-interactive use), then a saved
 * `.myrqen/config.json`, then detection — confirmed with one question in an
 * attended terminal and saved, or handed to the agent unsaved when nobody is
 * there to confirm it.
 *
 * A saved config is reused silently only when this machine wrote or confirmed
 * that exact run block. One that arrived with the repository is untrusted input:
 * an attended terminal is asked once, showing the exact command; otherwise it is
 * handed to the agent marked unconfirmed. Nothing here ever runs the command.
 */
export async function resolveRunConfig(
  repoRoot: string,
  options: { flags?: RunConfigFlags; discoveredPorts?: number[]; asJson?: boolean } = {}
): Promise<ResolvedRunConfig> {
  const existing = await readProjectConfig(repoRoot);
  const flags = options.flags ?? {};
  const hasFlags = Boolean(flags.startCommand || flags.appUrl || (flags.env && flags.env.length > 0));

  if (hasFlags) {
    const detected = existing?.run ? null : await detectRunConfig(repoRoot, { discoveredPorts: options.discoveredPorts ?? [] });
    const base = existing?.run ?? (detected ? fromDetected(detected) : null);
    const command = flags.startCommand ?? base?.command;
    const target = flags.appUrl ?? base?.url;
    if (!command || !target) {
      throw new Error(
        `Give both --start-command and --app-url the first time; ${BRAND.displayName} could not detect the ${command ? "address" : "start command"}.`
      );
    }
    const run = makeRunConfig({ command, target, env: flags.env ?? base?.env ?? [] }, "flags");
    await writeProjectConfig(repoRoot, { ...(existing ?? { version: 1 }), version: 1, run });
    await trustRunConfig(repoRoot, run);
    return { run, persisted: true, confirmed: true, asked: false };
  }

  if (existing?.run) return reuseSaved(repoRoot, existing.run, Boolean(options.asJson));

  const detected = await detectRunConfig(repoRoot, { discoveredPorts: options.discoveredPorts ?? [] });
  if (!detected) return { run: null, persisted: false, confirmed: false, asked: false };
  const proposal = fromDetected(detected);
  if (!proposal) return { run: null, persisted: false, confirmed: false, asked: false };

  if (options.asJson || !isInteractive()) return { run: proposal, persisted: false, confirmed: false, asked: false };

  write(`How to start this app (${detected.reasons.join("; ")}):`);
  field("  Command", proposal.command);
  field("  Address", proposal.url);
  if (proposal.env.length > 0) field("  Needs env", proposal.env.join(", "));
  let run: ProjectRunConfig | null = null;
  try {
    const accepted = await confirm("Use this for runtime checks, and remember it for this project?", { defaultYes: true });
    if (accepted) {
      run = { ...proposal, source: "confirmed" };
    } else {
      const command = await text(`Start command (empty to skip) [${proposal.command}]:`);
      if (command) {
        const target = (await text(`Port or loopback URL [${proposal.port}]:`)) ?? String(proposal.port);
        run = makeRunConfig({ command, target, env: proposal.env }, "edited");
      }
    }
  } catch (error) {
    // End of input or an invalid answer is "not now", never a failed scan.
    capabilityNote(error instanceof Error && !/abort/i.test(error.message) ? error.message : "No answer given.");
    run = null;
  }

  if (!run) {
    capabilityNote(`Not saved. Set it any time with "${BRAND.cliName} config set run.command <command>".`);
    return { run: proposal, persisted: false, confirmed: false, asked: true };
  }
  await writeProjectConfig(repoRoot, { ...(existing ?? { version: 1 }), version: 1, run });
  await trustRunConfig(repoRoot, run);
  capabilityNote(`Saved to ${BRAND.repoStateDirectoryName}/config.json. Change it with "${BRAND.cliName} config".`);
  return { run, persisted: true, confirmed: true, asked: true };
}

/**
 * A saved run block: trusted when this machine wrote or confirmed exactly this
 * block, otherwise treated as the repository's proposal. The file's own `source`
 * is not believed — "confirmed" in a committed file says nothing about this user.
 */
async function reuseSaved(repoRoot: string, saved: ProjectRunConfig, asJson: boolean): Promise<ResolvedRunConfig> {
  if (await isRunConfigTrusted(repoRoot, saved)) return { run: saved, persisted: true, confirmed: true, asked: false };
  const unconfirmed: ProjectRunConfig = { ...saved, source: "committed" };
  if (asJson || !isInteractive()) return { run: unconfirmed, persisted: true, confirmed: false, asked: false };

  write(`This repository's ${BRAND.repoStateDirectoryName}/config.json says how to start the app. It was not written or confirmed on this machine:`);
  field("  Command", saved.command);
  field("  Address", saved.url);
  if (saved.env.length > 0) field("  Needs env", saved.env.join(", "));
  let accepted = false;
  try {
    accepted = await confirm("Is this the right command to start the app for runtime checks?", { defaultYes: false });
  } catch {
    accepted = false;
  }
  if (!accepted) {
    capabilityNote(
      `Not confirmed. The agent is told not to run it. Set your own with "${BRAND.cliName} config set run.command <command>", or confirm this one later with "${BRAND.cliName} config trust".`
    );
    return { run: unconfirmed, persisted: true, confirmed: false, declined: true, asked: true };
  }
  await trustRunConfig(repoRoot, saved);
  return { run: saved, persisted: true, confirmed: true, asked: true };
}
