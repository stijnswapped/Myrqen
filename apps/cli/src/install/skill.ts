import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { BRAND, SKILL_BUNDLE_VERSION } from "@myrqen/brand";

export type AgentId = "claude-code" | "codex" | "opencode" | "portable";

export interface AgentTarget {
  id: AgentId;
  label: string;
  /** Directory that holds one folder per skill. */
  skillsDirectory: string;
  scope: "personal" | "project";
  /** A marker that suggests this agent is actually installed. */
  detectPaths: string[];
  slashInvocation: boolean;
}

const MANAGED_MARKER = ".myrqen-managed.json";

export function agentTargets(repoRoot: string): AgentTarget[] {
  const home = os.homedir();
  return [
    {
      id: "claude-code",
      label: "Claude Code",
      skillsDirectory: path.join(home, ".claude", "skills"),
      scope: "personal",
      detectPaths: [path.join(home, ".claude")],
      slashInvocation: true
    },
    {
      id: "claude-code",
      label: "Claude Code (this project)",
      skillsDirectory: path.join(repoRoot, ".claude", "skills"),
      scope: "project",
      detectPaths: [path.join(repoRoot, ".claude")],
      slashInvocation: true
    },
    {
      id: "codex",
      label: "Codex CLI",
      skillsDirectory: path.join(home, ".codex", "skills"),
      scope: "personal",
      detectPaths: [path.join(home, ".codex")],
      slashInvocation: false
    },
    {
      id: "opencode",
      label: "OpenCode",
      skillsDirectory: path.join(home, ".config", "opencode", "skills"),
      scope: "personal",
      detectPaths: [path.join(home, ".config", "opencode")],
      slashInvocation: false
    },
    {
      id: "portable",
      label: "Portable agent skills directory",
      skillsDirectory: path.join(home, ".agents", "skills"),
      scope: "personal",
      detectPaths: [path.join(home, ".agents")],
      slashInvocation: false
    }
  ];
}

async function exists(target: string): Promise<boolean> {
  try {
    await fs.access(target);
    return true;
  } catch {
    return false;
  }
}

export interface DetectedAgent extends AgentTarget {
  detected: boolean;
  installedVersion?: string;
  installedAt?: string;
  managed: boolean;
}

export async function detectAgents(repoRoot: string): Promise<DetectedAgent[]> {
  const results: DetectedAgent[] = [];
  for (const target of agentTargets(repoRoot)) {
    let detected = false;
    for (const candidate of target.detectPaths) {
      if (await exists(candidate)) {
        detected = true;
        break;
      }
    }
    const skillDirectory = path.join(target.skillsDirectory, BRAND.skillId);
    let installedVersion: string | undefined;
    let installedAt: string | undefined;
    let managed = false;
    try {
      const marker = JSON.parse(await fs.readFile(path.join(skillDirectory, MANAGED_MARKER), "utf8")) as {
        version?: string;
        installedAt?: string;
      };
      managed = true;
      if (marker.version) installedVersion = marker.version;
      if (marker.installedAt) installedAt = marker.installedAt;
    } catch {
      managed = false;
    }
    results.push({
      ...target,
      detected,
      managed,
      ...(installedVersion ? { installedVersion } : {}),
      ...(installedAt ? { installedAt } : {})
    });
  }
  return results;
}

/** Resolve the portable skill bundle that ships with this CLI. */
export async function skillSourceDirectory(): Promise<string> {
  const override = process.env.MYRQEN_SKILL_SOURCE;
  if (override && (await exists(path.join(override, "SKILL.md")))) return override;

  const here = path.dirname(fileURLToPath(import.meta.url));
  const candidates = [
    path.resolve(here, "..", "skill"),
    path.resolve(here, "..", "..", "skill"),
    path.resolve(here, "..", "..", "..", "packages", "skill", BRAND.skillId),
    path.resolve(process.cwd(), "packages", "skill", BRAND.skillId)
  ];
  for (const candidate of candidates) {
    if (await exists(path.join(candidate, "SKILL.md"))) return candidate;
  }
  throw new Error("The portable skill bundle could not be located next to this installation.");
}

async function copyTree(from: string, to: string): Promise<string[]> {
  const written: string[] = [];
  await fs.mkdir(to, { recursive: true });
  for (const entry of await fs.readdir(from, { withFileTypes: true })) {
    const source = path.join(from, entry.name);
    const destination = path.join(to, entry.name);
    if (entry.isDirectory()) {
      written.push(...(await copyTree(source, destination)));
      continue;
    }
    if (!entry.isFile()) continue;
    await fs.copyFile(source, destination);
    written.push(destination);
  }
  return written;
}

async function directoryDigest(directory: string): Promise<string> {
  const hash = crypto.createHash("sha256");
  const walk = async (current: string, prefix: string): Promise<void> => {
    const entries = (await fs.readdir(current, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (entry.name === MANAGED_MARKER) continue;
      const full = path.join(current, entry.name);
      const relative = path.posix.join(prefix, entry.name);
      if (entry.isDirectory()) {
        await walk(full, relative);
        continue;
      }
      hash.update(relative);
      hash.update(await fs.readFile(full));
    }
  };
  await walk(directory, "");
  return hash.digest("hex");
}

export interface InstallResult {
  target: AgentTarget;
  action: "installed" | "updated" | "unchanged" | "backed_up_and_installed" | "skipped";
  location: string;
  backupLocation?: string;
  fileCount: number;
}

/**
 * Installs the same portable bundle everywhere. A pre-existing directory that
 * Myrqen did not write is backed up first, never silently overwritten.
 */
export async function installSkill(target: AgentTarget, sourceDirectory: string): Promise<InstallResult> {
  const destination = path.join(target.skillsDirectory, BRAND.skillId);
  const markerPath = path.join(destination, MANAGED_MARKER);
  let backupLocation: string | undefined;
  let action: InstallResult["action"] = "installed";

  if (await exists(destination)) {
    const managed = await exists(markerPath);
    if (managed) {
      const currentDigest = await directoryDigest(destination).catch(() => "");
      const sourceDigest = await directoryDigest(sourceDirectory);
      if (currentDigest === sourceDigest) {
        return { target, action: "unchanged", location: destination, fileCount: 0 };
      }
      await fs.rm(destination, { recursive: true, force: true });
      action = "updated";
    } else {
      backupLocation = `${destination}.backup-${new Date().toISOString().replace(/[:.]/g, "-")}`;
      await fs.rename(destination, backupLocation);
      action = "backed_up_and_installed";
    }
  }

  const written = await copyTree(sourceDirectory, destination);
  const digest = await directoryDigest(destination);
  await fs.writeFile(
    markerPath,
    `${JSON.stringify(
      {
        managedBy: BRAND.displayName,
        version: SKILL_BUNDLE_VERSION,
        installedAt: new Date().toISOString(),
        digest
      },
      null,
      2
    )}\n`,
    "utf8"
  );

  return {
    target,
    action,
    location: destination,
    ...(backupLocation ? { backupLocation } : {}),
    fileCount: written.length
  };
}
