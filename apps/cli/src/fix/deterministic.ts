import fs from "node:fs/promises";
import path from "node:path";
import { BRAND } from "@myrqen/brand";
import type { Finding } from "@myrqen/contracts";
import { fixedIn } from "@myrqen/scan";

/**
 * Fixes Myrqen may apply itself, because they are mechanical and safe.
 *
 * Myrqen has no model: almost every remediation is the host agent's work, from a
 * plan this CLI writes. A small class of fixes is different — the change is fully
 * determined by the finding and cannot alter behaviour beyond the fix. Those are
 * applied here, on the fix branch only, and still go through `retest` before
 * anything is committed.
 *
 * Today that class is one thing: moving a dependency pinned inside an advisory
 * range to the first release that leaves it, *within the same major version*. A
 * major upgrade is an API change, so it is left to the agent and named in the
 * plan instead.
 */

export interface DeterministicEdit {
  file: string;
  description: string;
}

export interface DeterministicPlan {
  applicable: boolean;
  /** What will change, one line per edit. */
  edits: DeterministicEdit[];
  /** What the deterministic path deliberately leaves for the agent. */
  leftForAgent: string[];
  /** Follow-up the user must do that Myrqen will not (no network, no installs). */
  followUp: string[];
  apply?: () => Promise<string[]>;
}

/**
 * An installed package named in a dependency finding's evidence: `name@1.2.3`, scoped
 * names included. The first fixed release is not parsed from the text; it is read from
 * the scanner's advisory snapshot (`fixedIn`), so the CLI and the finding agree.
 */
const INSTALLED_ENTRY = /(?:^|[\s;,(])((?:@[a-z0-9][\w.~-]*\/)?[a-z0-9][\w.~-]*)@(\d+\.\d+\.\d+(?:[-+][\w.+-]*)?)/gi;

function parts(version: string): number[] {
  return version.split(".").map((part) => Number.parseInt(part, 10) || 0);
}

function greater(a: string, b: string): boolean {
  const left = parts(a);
  const right = parts(b);
  for (let index = 0; index < 3; index += 1) {
    if ((left[index] ?? 0) !== (right[index] ?? 0)) return (left[index] ?? 0) > (right[index] ?? 0);
  }
  return false;
}

/** `^1.2.3`, `~1.2.3`, `1.2.3`, `=1.2.3`: the shapes a mechanical bump may rewrite. */
const SIMPLE_RANGE = /^([\^~=]?)(\d+\.\d+\.\d+)$/;

export function isDependencyFinding(finding: Finding): boolean {
  return finding.category === "dependency_with_known_advisory" || (finding.tags ?? []).includes("dependency-advisory");
}

interface Affected {
  name: string;
  version: string;
}

function affectedFrom(finding: Finding): Affected[] {
  const evidence = [...finding.evidence, ...(finding.corroboration ?? [])];
  // The scanner states installed versions in `dependency` evidence; an agent's finding
  // may not use that kind, so its evidence is read whole.
  const dependencyEvidence = evidence.filter((item) => item.kind === "dependency");
  const descriptions = (dependencyEvidence.length > 0 ? dependencyEvidence : evidence).map((item) => item.description);
  const found = new Map<string, Affected>();
  for (const text of descriptions) {
    for (const match of text.matchAll(INSTALLED_ENTRY)) {
      if (!found.has(match[1]!)) found.set(match[1]!, { name: match[1]!, version: match[2]! });
    }
  }
  return [...found.values()];
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export async function planDeterministicFix(repoRoot: string, finding: Finding): Promise<DeterministicPlan> {
  const none: DeterministicPlan = { applicable: false, edits: [], leftForAgent: [], followUp: [] };
  if (!isDependencyFinding(finding)) return none;

  const manifestPath = path.join(repoRoot, "package.json");
  let raw: string;
  let manifest: { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
  try {
    raw = await fs.readFile(manifestPath, "utf8");
    manifest = JSON.parse(raw);
  } catch {
    return none;
  }

  const edits: DeterministicEdit[] = [];
  const leftForAgent: string[] = [];
  const replacements: Array<{ name: string; from: string; to: string }> = [];

  for (const entry of affectedFrom(finding)) {
    const range = manifest.dependencies?.[entry.name] ?? manifest.devDependencies?.[entry.name];
    if (!range) continue;
    const fixed = fixedIn(entry.name, entry.version);
    const simple = SIMPLE_RANGE.exec(range.trim());
    if (!fixed || !greater(fixed, entry.version)) {
      leftForAgent.push(`${entry.name}: the advisory data names no release that fixes ${entry.version}; upgrade it by hand.`);
      continue;
    }
    if (!simple) {
      leftForAgent.push(`${entry.name}: the range "${range}" is not a simple version, so it is not rewritten mechanically.`);
      continue;
    }
    if (parts(fixed)[0] !== parts(simple[2]!)[0]) {
      leftForAgent.push(
        `${entry.name}: the first fixed release (${fixed}) is a new major version; that is an API change for the agent to make and test.`
      );
      continue;
    }
    const to = `${simple[1]}${fixed}`;
    replacements.push({ name: entry.name, from: range, to });
    edits.push({ file: "package.json", description: `${entry.name} ${range} -> ${to}` });
  }

  if (replacements.length === 0) return { ...none, leftForAgent };

  const lockfiles = ["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "bun.lock"];
  const presentLockfiles: string[] = [];
  for (const lockfile of lockfiles) {
    try {
      await fs.access(path.join(repoRoot, lockfile));
      presentLockfiles.push(lockfile);
    } catch {
      // absent
    }
  }

  return {
    applicable: true,
    edits,
    leftForAgent,
    followUp:
      presentLockfiles.length > 0
        ? [
            `Run your package manager's install to update ${presentLockfiles.join(", ")}, then run the test suite. ${BRAND.displayName} does not install packages.`
          ]
        : [`Run your package manager's install and the test suite. ${BRAND.displayName} does not install packages.`],
    apply: async () => {
      let next = raw;
      for (const replacement of replacements) {
        const pattern = new RegExp(`("${escapeRegExp(replacement.name)}"\\s*:\\s*")${escapeRegExp(replacement.from)}(")`, "g");
        next = next.replace(pattern, `$1${replacement.to}$2`);
      }
      // Refuse to write something that no longer parses.
      JSON.parse(next);
      await fs.writeFile(manifestPath, next, "utf8");
      return ["package.json"];
    }
  };
}
