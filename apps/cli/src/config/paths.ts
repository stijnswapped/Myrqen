import os from "node:os";
import path from "node:path";
import { BRAND } from "@myrqen/brand";

/** Platform-correct config directory. No product data is written outside it. */
export function configDirectory(): string {
  const override = process.env.MYRQEN_CONFIG_DIR;
  if (override) return path.resolve(override);

  if (process.platform === "win32") {
    const base = process.env.APPDATA ?? path.join(os.homedir(), "AppData", "Roaming");
    return path.join(base, BRAND.displayName);
  }
  if (process.platform === "darwin") {
    return path.join(os.homedir(), "Library", "Application Support", BRAND.displayName);
  }
  const xdg = process.env.XDG_CONFIG_HOME ?? path.join(os.homedir(), ".config");
  return path.join(xdg, BRAND.configDirectoryName);
}

export function configFile(): string {
  return path.join(configDirectory(), "config.json");
}

export function credentialFallbackFile(): string {
  return path.join(configDirectory(), "credential.json");
}

export function stateDirectory(repoRoot: string): string {
  return path.join(repoRoot, BRAND.repoStateDirectoryName);
}

export function sessionDirectory(repoRoot: string, localReportId: string): string {
  return assertInsideStateDirectory(repoRoot, path.join(stateDirectory(repoRoot), "sessions", assertLocalReportId(localReportId)));
}

export function reportDirectory(repoRoot: string, localReportId: string): string {
  return assertInsideStateDirectory(repoRoot, path.join(stateDirectory(repoRoot), "reports", assertLocalReportId(localReportId)));
}

/** The committable baseline. Outside the ignored sessions/ and reports/ directories on purpose. */
export function baselineFile(repoRoot: string): string {
  return path.join(stateDirectory(repoRoot), "baseline.json");
}

export function currentSessionPointer(repoRoot: string): string {
  return path.join(stateDirectory(repoRoot), "current-session");
}

/*
 * Ids read back from `.myrqen/` are repository content: a repository can ship a
 * `current-session` pointer, a session file, or a fix record of its own. Every id
 * is checked against the shape the CLI itself generates before it becomes part of
 * a path, and every such path is asserted to stay inside `<repoRoot>/.myrqen`.
 */
const LOCAL_REPORT_ID = /^rpt_[0-9a-f-]{36}$/;
const FINDING_ID = /^[A-Za-z0-9._-]{1,32}$/;
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/;

function shown(value: unknown): string {
  return JSON.stringify(String(value).slice(0, 80));
}

export function isValidLocalReportId(value: unknown): value is string {
  return typeof value === "string" && LOCAL_REPORT_ID.test(value);
}

export function isValidFindingId(value: unknown): value is string {
  return typeof value === "string" && FINDING_ID.test(value) && !value.includes("..") && !/^\.+$/.test(value);
}

export function assertLocalReportId(value: unknown): string {
  if (!isValidLocalReportId(value)) throw new Error(`${shown(value)} is not a valid local report id (expected rpt_ followed by a UUID).`);
  return value;
}

export function assertFindingId(value: unknown): string {
  if (!isValidFindingId(value)) throw new Error(`${shown(value)} is not a valid finding id.`);
  return value;
}

/** Throws unless `candidate` resolves to a path inside `<repoRoot>/.myrqen`. */
export function assertInsideStateDirectory(repoRoot: string, candidate: string): string {
  const base = path.resolve(stateDirectory(repoRoot));
  const resolved = path.resolve(candidate);
  if (!resolved.startsWith(`${base}${path.sep}`)) {
    throw new Error(`Refusing to use ${resolved}: it is outside ${base}.`);
  }
  return resolved;
}

/**
 * A plain path relative to the repository root that stays inside it and outside
 * the state directory: no absolute paths, drive letters, `..` segments, or
 * control characters.
 */
export function isSafeRepoRelativePath(value: unknown): value is string {
  if (typeof value !== "string" || value.length === 0 || value.length > 1024) return false;
  if (CONTROL_CHARACTERS.test(value)) return false;
  if (path.isAbsolute(value) || path.win32.isAbsolute(value) || /^[A-Za-z]:/.test(value)) return false;
  const segments = value.split(/[\\/]+/);
  if (segments.some((segment) => segment === "..")) return false;
  if (segments.includes(BRAND.repoStateDirectoryName)) return false;
  return segments.some((segment) => segment !== "" && segment !== ".");
}
