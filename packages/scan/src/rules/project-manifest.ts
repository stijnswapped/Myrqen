import fs from "node:fs";
import path from "node:path";
import type { ParsedFile } from "../ast/parse.js";

/**
 * The dependency names a source file's project declares.
 *
 * Read from the nearest `package.json` above the file and from the repository root,
 * because a workspace member declares its own framework while the root often declares
 * the shared middleware. Read synchronously and memoised per directory: rules run per
 * file, and a repository has a handful of manifests.
 *
 * `null` means no manifest declared any dependency at all — which is not the same as
 * "declares no rate limiter", and the rules that ask about absence treat it as unknown.
 */
const CACHE = new Map<string, Set<string> | null>();

export function declaredDependencies(file: ParsedFile): Set<string> | null {
  const root = repositoryRoot(file);
  const names = new Set<string>();
  let sawAny = false;
  for (const manifest of manifestsFor(file, root)) {
    const deps = readManifest(manifest);
    if (!deps) continue;
    sawAny = true;
    for (const name of deps) names.add(name);
  }
  return sawAny && names.size > 0 ? names : null;
}

function repositoryRoot(file: ParsedFile): string {
  const relative = file.relativePath.split("/").join(path.sep);
  return file.absolutePath.endsWith(relative) ? file.absolutePath.slice(0, file.absolutePath.length - relative.length) : path.dirname(file.absolutePath);
}

function manifestsFor(file: ParsedFile, root: string): string[] {
  const found: string[] = [];
  let directory = path.dirname(file.absolutePath);
  const stop = path.resolve(root);
  for (let depth = 0; depth < 12; depth += 1) {
    const candidate = path.join(directory, "package.json");
    if (fs.existsSync(candidate)) found.push(candidate);
    if (path.resolve(directory) === stop) break;
    const parent = path.dirname(directory);
    if (parent === directory) break;
    directory = parent;
  }
  return found;
}

function readManifest(manifest: string): Set<string> | null {
  // Keyed on the file's identity *and* its modification, so a long-lived process that
  // scans the same repository twice never answers from a manifest that has changed.
  let key = manifest;
  try {
    const stat = fs.statSync(manifest);
    key = `${manifest}:${stat.mtimeMs}:${stat.size}`;
  } catch {
    return null;
  }
  if (CACHE.has(key)) return CACHE.get(key) ?? null;
  let names: Set<string> | null = null;
  try {
    const parsed = JSON.parse(fs.readFileSync(manifest, "utf8")) as Record<string, unknown>;
    names = new Set<string>();
    for (const field of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
      const block = parsed[field];
      if (block && typeof block === "object") for (const name of Object.keys(block)) names.add(name);
    }
  } catch {
    names = null;
  }
  CACHE.set(key, names);
  return names;
}

/** Forget memoised manifests; tests rewrite them between cases. */
export function resetManifestCache(): void {
  CACHE.clear();
}
