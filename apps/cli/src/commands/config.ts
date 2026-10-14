import { BRAND } from "@myrqen/brand";
import {
  isValidEnvName,
  makeRunConfig,
  normalizeEnvNames,
  normalizeRunTarget,
  projectConfigFile,
  readProjectConfig,
  writeProjectConfig,
  type ProjectConfig,
  type ProjectRunConfig
} from "../config/project-config.js";
import { isRunConfigTrusted, trustRunConfig } from "../config/run-trust.js";
import { readConfig } from "../config/store.js";
import { findRepoRoot, firstReachable } from "../discovery/project.js";
import { detectRunConfig } from "../discovery/runtime.js";
import { blank, bullet, capabilityNote, field, heading, json, style, write } from "../ui/output.js";
import { confirm, isInteractive } from "../ui/prompt.js";

const KEYS = ["run.command", "run.url", "run.port", "run.env"] as const;
type Key = (typeof KEYS)[number];

function usage(): string {
  return [
    `Usage: ${BRAND.cliName} config                      show this project's settings`,
    `       ${BRAND.cliName} config detect               show what would be detected, and offer to save it`,
    `       ${BRAND.cliName} config set <key> <value>    keys: ${KEYS.join(", ")}`,
    `       ${BRAND.cliName} config trust                confirm the saved start command on this machine`,
    `       ${BRAND.cliName} config reset                forget how to start the app (asked again next scan)`,
    `       ${BRAND.cliName} config set-url <url>        app base URL for account and sync`,
    `       ${BRAND.cliName} config telemetry <on|off>`
  ].join("\n");
}

async function show(repoRoot: string, asJson: boolean): Promise<void> {
  const project = await readProjectConfig(repoRoot);
  const global = await readConfig();
  const reachable = project?.run ? (await firstReachable([project.run.url])).length > 0 : false;
  const confirmed = project?.run ? await isRunConfigTrusted(repoRoot, project.run) : false;
  if (asJson) {
    json({
      file: projectConfigFile(repoRoot),
      project: project ?? null,
      appReachable: reachable,
      runConfirmed: confirmed,
      global: { apiBaseUrl: global.apiBaseUrl, telemetry: global.telemetry?.enabled !== false }
    });
    return;
  }
  heading("config");
  field("Project file", projectConfigFile(repoRoot));
  if (project?.run) {
    field("Start command", `${project.run.command}${confirmed ? "" : style.warn(` (unconfirmed on this machine; "${BRAND.cliName} config trust" confirms it)`)}`);
    field("App address", `${project.run.url}${reachable ? style.ok(" (answering)") : style.dim(" (not running)")}`);
    field("Env names", project.run.env.length > 0 ? project.run.env.join(", ") : "none");
    field("Decided", `${project.run.source}, ${project.run.updatedAt.slice(0, 10)}`);
  } else {
    capabilityNote(`Not set. The next scan detects it and asks once; or run "${BRAND.cliName} config detect".`);
  }
  blank();
  field("App base URL", global.apiBaseUrl);
  field("Telemetry", global.telemetry?.enabled === false ? "off" : "on");
}

async function detect(repoRoot: string, asJson: boolean): Promise<void> {
  const detected = await detectRunConfig(repoRoot);
  if (asJson) {
    json({ detected });
    return;
  }
  heading("config detect");
  if (!detected) {
    write(`Nothing to start was found: no dev/start script in package.json and no server entry file.`);
    write(`Set it yourself with "${BRAND.cliName} config set run.command <command>" and "${BRAND.cliName} config set run.url <port>".`);
    return;
  }
  field("Start command", detected.command);
  field("App address", detected.url);
  field("Env names", detected.env.length > 0 ? detected.env.join(", ") : "none");
  for (const reason of detected.reasons) bullet(reason);
  if (!isInteractive()) return;
  if (await confirm("Save this as the project's run configuration?", { defaultYes: true })) {
    await save(repoRoot, makeRunConfig({ command: detected.command, target: detected.port, env: detected.env.filter(isValidEnvName) }, "confirmed"));
  }
}

async function save(repoRoot: string, run: ProjectRunConfig | undefined): Promise<void> {
  const existing = (await readProjectConfig(repoRoot)) ?? { version: 1 };
  const next: ProjectConfig = { ...existing, version: 1 };
  if (run) next.run = run;
  else delete next.run;
  await writeProjectConfig(repoRoot, next);
  if (run) await trustRunConfig(repoRoot, run);
  write(`${style.ok("Saved")} ${projectConfigFile(repoRoot)}`);
}

/**
 * Confirm the saved run settings on this machine, typically after the agent has
 * shown the user the exact command from a committed config and the user agreed.
 * Running this is the confirmation; it never starts anything.
 */
async function trust(repoRoot: string, asJson: boolean): Promise<void> {
  const run = (await readProjectConfig(repoRoot))?.run;
  if (!run) throw new Error(`There are no usable run settings in ${projectConfigFile(repoRoot)} to confirm.`);
  await trustRunConfig(repoRoot, run);
  if (asJson) {
    json({ file: projectConfigFile(repoRoot), confirmed: true, run: { command: run.command, url: run.url, env: run.env } });
    return;
  }
  write(`${style.ok("Confirmed")} on this machine:`);
  field("  Command", run.command);
  field("  Address", run.url);
  if (run.env.length > 0) field("  Needs env", run.env.join(", "));
  capabilityNote("Any later change to this file has to be confirmed again.");
}

async function set(repoRoot: string, key: string, values: string[], asJson: boolean): Promise<void> {
  if (!KEYS.includes(key as Key)) throw new Error(`Unknown key "${key}".\n${usage()}`);
  if (values.length === 0) throw new Error(`"config set ${key}" needs a value.`);
  const value = values.join(" ");

  const existing = (await readProjectConfig(repoRoot))?.run;
  // A first `set` fills the parts it does not name from detection, so setting
  // only the command does not leave the address undefined.
  const detected = existing ? null : await detectRunConfig(repoRoot);
  const base = existing ?? (detected
    ? makeRunConfig({ command: detected.command, target: detected.port, env: detected.env.filter(isValidEnvName) }, "detected")
    : null);

  let command = base?.command;
  let target: string | number | undefined = base?.url;
  let env = base?.env ?? [];
  if (key === "run.command") command = value;
  if (key === "run.url" || key === "run.port") target = normalizeRunTarget(value).url;
  if (key === "run.env") env = value.trim() === "-" ? [] : normalizeEnvNames(values);

  if (!command) throw new Error(`Set run.command first: nothing to start was detected in this project.`);
  if (target === undefined) throw new Error(`Set run.url too: the app's address could not be detected.`);

  const run = makeRunConfig({ command, target, env }, "edited");
  await writeProjectConfig(repoRoot, { ...((await readProjectConfig(repoRoot)) ?? { version: 1 }), version: 1, run });
  // Whoever sets a value here has seen it, so the result is confirmed on this machine.
  await trustRunConfig(repoRoot, run);
  if (asJson) json({ file: projectConfigFile(repoRoot), run });
  else write(`${style.ok("Saved")} ${key} in ${projectConfigFile(repoRoot)}`);
}

export async function projectConfigCommand(
  subcommand: string | undefined,
  args: string[],
  options: { asJson?: boolean } = {}
): Promise<boolean> {
  const repoRoot = await findRepoRoot(process.cwd());
  const asJson = Boolean(options.asJson);
  switch (subcommand) {
    case undefined:
    case "show":
      await show(repoRoot, asJson);
      return true;
    case "detect":
      await detect(repoRoot, asJson);
      return true;
    case "set":
      await set(repoRoot, args[0] ?? "", args.slice(1), asJson);
      return true;
    case "trust":
      await trust(repoRoot, asJson);
      return true;
    case "reset":
      await save(repoRoot, undefined);
      return true;
    case "help":
      write(usage());
      return true;
    default:
      return false;
  }
}

export { usage as configUsage };
