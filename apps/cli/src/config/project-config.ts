import fs from "node:fs/promises";
import net from "node:net";
import path from "node:path";
import { normalizeHttpTarget } from "@myrqen/policy";
import { warn } from "../ui/output.js";
import { stateDirectory } from "./paths.js";

/**
 * `.myrqen/config.json`: how this project's app is run, decided once.
 *
 * Unlike `local.json` (a personal binding) and `sessions/` (scan state), this
 * file is safe to commit: it holds a start command, a loopback URL, and the
 * *names* of the environment variables the app needs. A teammate who clones the
 * repository inherits the answer instead of being asked the same question.
 *
 * It cannot widen scope. The URL must be loopback; anything else is refused here,
 * because the only way an external origin enters a scan is the exact-origin
 * authorization gate, and a config file is not that gate.
 */

export type RunConfigSource = "detected" | "confirmed" | "flags" | "edited" | "committed";

export interface ProjectRunConfig {
  command: string;
  url: string;
  port: number;
  env: string[];
  source: RunConfigSource;
  updatedAt: string;
}

export interface ProjectConfig {
  version: 1;
  run?: ProjectRunConfig;
}

export function projectConfigFile(repoRoot: string): string {
  return path.join(stateDirectory(repoRoot), "config.json");
}

const MAX_COMMAND_LENGTH = 500;
const MAX_ENV_NAMES = 64;
const MAX_ENV_NAME_LENGTH = 128;
const SOURCES: readonly RunConfigSource[] = ["detected", "confirmed", "flags", "edited", "committed"];

/**
 * C0 and C1 controls (newlines and tabs included), DEL, and the Unicode
 * bidirectional overrides and isolates. A start command is shown to a person who
 * decides whether to run it, so it must read the same on screen as it does to a
 * shell: no second line hidden after a newline, no text reordered by U+202E.
 */
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069]/;

/**
 * `.myrqen/config.json`, validated as untrusted input.
 *
 * The file is committed, so it arrives with the repository and is exactly as
 * trustworthy as the repository: not at all. Every field goes through the same
 * validators a write uses; an unusable command or address drops the whole run
 * block, an invalid environment name drops that name, and each drop is said once.
 * `source` and `port` are never taken from the file: the port is derived from the
 * validated URL, and the source is "committed" until this machine confirms it.
 */
export async function readProjectConfig(repoRoot: string, options: { warnings?: string[] } = {}): Promise<ProjectConfig | null> {
  let raw: string;
  try {
    raw = await fs.readFile(projectConfigFile(repoRoot), "utf8");
  } catch {
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`${projectConfigFile(repoRoot)} is not valid JSON. Fix it by hand or remove it to be asked again.`);
  }
  if (!isRecord(parsed) || parsed.version !== 1) return null;

  const warnings: string[] = [];
  const config: ProjectConfig = { version: 1 };
  if (parsed.run !== undefined) {
    const run = sanitizeRunConfig(parsed.run, warnings);
    if (run) config.run = run;
  }
  if (warnings.length > 0) {
    const lines = warnings.map((line) => `${projectConfigFile(repoRoot)}: ${line}`);
    if (options.warnings) options.warnings.push(...lines);
    else for (const line of lines) warn(line);
  }
  return config;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The run block from an untrusted file, or null when it cannot be used safely. */
export function sanitizeRunConfig(value: unknown, warnings: string[]): ProjectRunConfig | null {
  if (!isRecord(value)) {
    warnings.push("the run block is not an object and was ignored.");
    return null;
  }
  let command: string;
  try {
    if (typeof value.command !== "string") throw new Error("The start command is missing or not text.");
    command = normalizeCommand(value.command);
  } catch (error) {
    warnings.push(`${messageOf(error)} The run settings were ignored.`);
    return null;
  }
  let target: { url: string; port: number };
  try {
    if (typeof value.url !== "string") throw new Error("The app address is missing or not text.");
    target = normalizeRunTarget(value.url);
  } catch (error) {
    warnings.push(`${messageOf(error)} The run settings were ignored.`);
    return null;
  }
  const env: string[] = [];
  const rawEnv = Array.isArray(value.env) ? value.env : [];
  if (value.env !== undefined && !Array.isArray(value.env)) warnings.push("run.env is not a list and was ignored.");
  let dropped = 0;
  for (const entry of rawEnv) {
    if (typeof entry === "string" && isValidEnvName(entry) && !env.includes(entry) && env.length < MAX_ENV_NAMES) env.push(entry);
    else dropped += 1;
  }
  // The rejected entries are counted, never echoed: one may be a NAME=value pair.
  if (dropped > 0) warnings.push(`${dropped} entr${dropped === 1 ? "y" : "ies"} in run.env ${dropped === 1 ? "is" : "are"} not a valid environment variable name and ${dropped === 1 ? "was" : "were"} dropped.`);
  const source = typeof value.source === "string" && (SOURCES as readonly string[]).includes(value.source) ? (value.source as RunConfigSource) : "committed";
  const updatedAt = typeof value.updatedAt === "string" && !Number.isNaN(Date.parse(value.updatedAt)) ? new Date(value.updatedAt).toISOString() : new Date(0).toISOString();
  return { command, url: target.url, port: target.port, env, source, updatedAt };
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : "Invalid value.";
}

export async function writeProjectConfig(repoRoot: string, config: ProjectConfig): Promise<void> {
  await fs.mkdir(stateDirectory(repoRoot), { recursive: true });
  await fs.writeFile(projectConfigFile(repoRoot), `${JSON.stringify(config, null, 2)}\n`, "utf8");
}

/**
 * Machine-local loopback only: `localhost`, 127.0.0.0/8, and `::1`.
 *
 * Narrower than the policy's notion of local on purpose. `*.localhost` and the
 * Docker host aliases are resolved through DNS on most machines, and an address
 * from a committed file is fetched by this CLI on the user's own machine, so
 * only names that cannot resolve anywhere else are accepted.
 */
export function isStrictLoopbackHost(hostname: string): boolean {
  const host = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (host === "localhost") return true;
  if (net.isIP(host) === 4) return host.split(".")[0] === "127";
  if (net.isIP(host) === 6) return host === "::1" || host === "0:0:0:0:0:0:0:1";
  return false;
}

/** Accept a port or a URL; return a loopback URL and its port, or throw. */
export function normalizeRunTarget(input: string | number): { url: string; port: number } {
  const text = String(input).trim();
  if (/^\d{2,5}$/.test(text)) {
    const port = Number(text);
    if (port < 1 || port > 65535) throw new Error(`${text} is not a valid port.`);
    return { url: `http://127.0.0.1:${port}`, port };
  }
  let normalized;
  try {
    normalized = normalizeHttpTarget(text);
  } catch (error) {
    throw new Error(`"${text.slice(0, 200)}" is not a usable URL: ${error instanceof Error ? error.message : "parse error"}`);
  }
  if (!normalized.local || !isStrictLoopbackHost(normalized.hostname)) {
    throw new Error(
      `${normalized.origin} is not a loopback address. The app under test runs locally; an external origin can only be added through "target authorize" during a scan.`
    );
  }
  const port = Number(new URL(normalized.origin).port || (normalized.origin.startsWith("https:") ? 443 : 80));
  return { url: normalized.origin, port };
}

/** Throws unless `url` is a strict loopback http(s) origin. Called right before any fetch. */
export function assertLoopbackUrl(url: string): void {
  normalizeRunTarget(url);
}

const ENV_NAME = /^[A-Z_][A-Z0-9_]*$/;

export function isValidEnvName(name: string): boolean {
  return name.length <= MAX_ENV_NAME_LENGTH && ENV_NAME.test(name);
}

/** Names only. A value smuggled in as NAME=value is refused rather than stored. */
export function normalizeEnvNames(values: readonly string[]): string[] {
  const names = new Set<string>();
  for (const value of values.flatMap((entry) => entry.split(","))) {
    const name = value.trim();
    if (!name) continue;
    if (name.includes("=")) {
      throw new Error(`"${name.split("=")[0]}=…" looks like a value. Store variable names only; values stay in your own environment.`);
    }
    if (!isValidEnvName(name)) throw new Error(`"${name}" is not a valid environment variable name (A-Z, 0-9 and _, not starting with a digit).`);
    names.add(name);
  }
  if (names.size > MAX_ENV_NAMES) throw new Error(`At most ${MAX_ENV_NAMES} environment variable names can be stored.`);
  return [...names];
}

export function normalizeCommand(input: string): string {
  const command = input.trim();
  if (!command) throw new Error("A start command cannot be empty.");
  if (command.length > MAX_COMMAND_LENGTH) throw new Error(`That start command is longer than ${MAX_COMMAND_LENGTH} characters.`);
  if (CONTROL_CHARACTERS.test(command)) {
    throw new Error("That start command contains a control character (a newline, a tab, or a direction override). Give it as one plain line.");
  }
  return command;
}

export function makeRunConfig(
  input: { command: string; target: string | number; env?: readonly string[] },
  source: RunConfigSource,
  now = new Date()
): ProjectRunConfig {
  const command = normalizeCommand(input.command);
  const { url, port } = normalizeRunTarget(input.target);
  return { command, url, port, env: normalizeEnvNames(input.env ?? []), source, updatedAt: now.toISOString() };
}
