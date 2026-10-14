import fs from "node:fs/promises";
import path from "node:path";

/**
 * Installed versions, read from whichever lockfile the project has.
 *
 * A manifest says what a project will accept; a lockfile says what it got. Every
 * advisory comparison is only as good as the version it compares, so the lockfile is
 * read whenever one exists and the manifest is a fallback, not a peer.
 *
 * Four formats, each parsed by hand rather than through a YAML or lockfile library,
 * because the scanner ships with no runtime dependency beyond TypeScript and needs
 * only `name → version` from each:
 *
 *  - `package-lock.json` / `npm-shrinkwrap.json`, versions 1 (nested `dependencies`) and
 *    2–3 (flat `packages` keyed by `node_modules/…` path);
 *  - `pnpm-lock.yaml`, the v5 (`/name/1.2.3`), v6 (`/name@1.2.3`) and v9 (`name@1.2.3`)
 *    package-key spellings;
 *  - `yarn.lock`, classic (v1) and Berry (`"name@npm:^1"` with `version: 1.2.3`);
 *  - `bun.lock`, the text lockfile (JSON with trailing commas). The older binary
 *    `bun.lockb` cannot be read, and that is said rather than skipped silently.
 *
 * A package installed at several versions appears once per version.
 */
export interface InstalledPackage {
  name: string;
  version: string;
  /** Marked as a development dependency by the lockfile, where the format records it. */
  dev: boolean;
}

export interface LockfileRead {
  file: string | null;
  packages: InstalledPackage[];
  /** Something the reader could not do, worded for the coverage list. */
  note?: string;
}

const CANDIDATES = ["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb"];

export async function readLockfile(repoRoot: string): Promise<LockfileRead> {
  for (const name of CANDIDATES) {
    const file = path.join(repoRoot, name);
    let text: string;
    try {
      if (name === "bun.lockb") {
        await fs.access(file);
        return {
          file: name,
          packages: [],
          note: "The project's lockfile is bun.lockb, a binary format this scanner cannot read; installed versions were taken from package.json ranges instead. Running `bun install --save-text-lockfile` produces a bun.lock it can read."
        };
      }
      text = await fs.readFile(file, "utf8");
    } catch {
      continue;
    }
    try {
      const packages = parseLockfile(name, text);
      return { file: name, packages: dedupe(packages) };
    } catch (error) {
      return {
        file: name,
        packages: [],
        note: `${name} could not be read (${error instanceof Error ? error.message : "unknown error"}); installed versions were taken from package.json ranges instead.`
      };
    }
  }
  return { file: null, packages: [] };
}

export function parseLockfile(name: string, text: string): InstalledPackage[] {
  if (name === "package-lock.json" || name === "npm-shrinkwrap.json") return parseNpm(text);
  if (name === "pnpm-lock.yaml") return parsePnpm(text);
  if (name === "yarn.lock") return parseYarn(text);
  if (name === "bun.lock") return parseBun(text);
  return [];
}

function parseNpm(text: string): InstalledPackage[] {
  const lock = JSON.parse(text) as {
    packages?: Record<string, { version?: string; dev?: boolean; name?: string; link?: boolean }>;
    dependencies?: Record<string, NpmV1Entry>;
  };
  const out: InstalledPackage[] = [];
  if (lock.packages) {
    for (const [key, entry] of Object.entries(lock.packages)) {
      if (!key || !entry.version || entry.link) continue;
      const index = key.lastIndexOf("node_modules/");
      if (index === -1) continue;
      const name = entry.name ?? key.slice(index + "node_modules/".length);
      out.push({ name, version: entry.version, dev: Boolean(entry.dev) });
    }
    return out;
  }
  const walk = (dependencies: Record<string, NpmV1Entry> | undefined): void => {
    for (const [name, entry] of Object.entries(dependencies ?? {})) {
      if (entry.version && !/^(?:file|link|git)/.test(entry.version)) out.push({ name, version: entry.version, dev: Boolean(entry.dev) });
      walk(entry.dependencies);
    }
  };
  walk(lock.dependencies);
  return out;
}

interface NpmV1Entry {
  version?: string;
  dev?: boolean;
  dependencies?: Record<string, NpmV1Entry>;
}

/**
 * Package keys under `packages:` (and `snapshots:` in v9). Only the key is needed:
 * name and version are both in it, and `dev: true` sits a few lines below in v5–v6.
 */
function parsePnpm(text: string): InstalledPackage[] {
  const out: InstalledPackage[] = [];
  const lines = text.split(/\r?\n/);
  let section = "";
  let current: InstalledPackage | null = null;
  for (const line of lines) {
    if (/^\S/.test(line)) {
      section = line.replace(/:.*$/, "");
      current = null;
      continue;
    }
    if (section !== "packages" && section !== "snapshots") continue;
    const key = /^ {2}(['"]?)(\/?[^\s'"]+)\1:\s*$/.exec(line);
    if (key) {
      current = pnpmKey(key[2]!);
      if (current) out.push(current);
      continue;
    }
    if (current && /^ {4}dev: true\s*$/.test(line)) current.dev = true;
  }
  return out;
}

function pnpmKey(raw: string): InstalledPackage | null {
  // Strip peer-dependency suffixes: `(react@18.2.0)` in v6/v9, `_react@18.2.0` in v5.
  const key = raw.replace(/\(.*$/, "");
  const v6 = /^\/?((?:@[^/]+\/)?[^@/]+)@([^@/]+)$/.exec(key);
  if (v6) return { name: v6[1]!, version: v6[2]!.replace(/_.*$/, ""), dev: false };
  const v5 = /^\/((?:@[^/]+\/)?[^/]+)\/([^/]+)$/.exec(key);
  if (v5) return { name: v5[1]!, version: v5[2]!.replace(/_.*$/, ""), dev: false };
  return null;
}

/** Yarn classic and Berry share a shape: a header naming the specs, then a version line. */
function parseYarn(text: string): InstalledPackage[] {
  const out: InstalledPackage[] = [];
  let names: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    if (line.startsWith("#") || line.trim() === "") continue;
    if (/^\S/.test(line) && line.trimEnd().endsWith(":")) {
      if (line.startsWith("__metadata")) {
        names = [];
        continue;
      }
      names = [
        ...new Set(
          line
            .trimEnd()
            .slice(0, -1)
            .split(/,\s*/)
            .map((spec) => spec.replace(/^["']|["']$/g, ""))
            .map(specName)
            .filter((name): name is string => Boolean(name))
        )
      ];
      continue;
    }
    const version = /^\s+version:?\s+"?([^"\s]+)"?\s*$/.exec(line);
    if (version && names.length > 0) {
      for (const name of names) out.push({ name, version: version[1]!, dev: false });
      names = [];
    }
  }
  return out;
}

/** `lodash@^4.17.0`, `@scope/pkg@npm:^1.0.0`, `pkg@patch:pkg@npm%3A1.0.0#…` → the package name. */
function specName(spec: string): string | null {
  const at = spec.indexOf("@", spec.startsWith("@") ? 1 : 0);
  if (at <= 0) return null;
  const name = spec.slice(0, at);
  const range = spec.slice(at + 1);
  if (/^(?:workspace|link|portal|file|patch|exec):/.test(range)) return null;
  return name;
}

/** bun.lock is JSON with trailing commas: `"packages": { "name": ["name@1.2.3", …] }`. */
function parseBun(text: string): InstalledPackage[] {
  const json = JSON.parse(text.replace(/,(\s*[}\]])/g, "$1")) as { packages?: Record<string, unknown[]> };
  const out: InstalledPackage[] = [];
  for (const entry of Object.values(json.packages ?? {})) {
    const id = Array.isArray(entry) ? entry[0] : null;
    if (typeof id !== "string") continue;
    const at = id.lastIndexOf("@");
    if (at <= 0) continue;
    const version = id.slice(at + 1);
    if (!/^\d/.test(version)) continue;
    out.push({ name: id.slice(0, at), version, dev: false });
  }
  return out;
}

function dedupe(packages: InstalledPackage[]): InstalledPackage[] {
  const seen = new Map<string, InstalledPackage>();
  for (const entry of packages) {
    const key = `${entry.name}@${entry.version}`;
    const existing = seen.get(key);
    // Installed once as a runtime dependency is enough to make it a runtime package.
    if (!existing) seen.set(key, { ...entry });
    else if (!entry.dev) seen.set(key, { ...existing, dev: false });
  }
  return [...seen.values()].sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
}
