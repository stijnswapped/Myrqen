import fs from "node:fs/promises";
import path from "node:path";
import { BRAND } from "@myrqen/brand";
import type { WorkspaceKind } from "@myrqen/contracts";

export interface TeamBinding {
  version: 1;
  kind: "team";
  workspaceId: string;
  projectId: string;
}

export interface PersonalBinding {
  version: 1;
  kind: "personal";
  workspaceId: string;
  projectId: string;
  workspaceName?: string;
  projectName?: string;
}

export type BindingSource = "team_committed" | "personal_local" | "unbound";

export interface ResolvedBinding {
  source: Exclude<BindingSource, "unbound">;
  workspaceKind: WorkspaceKind;
  workspaceId: string;
  projectId: string;
  workspaceName?: string;
  projectName?: string;
  /** Absolute path to the file that provided the binding. */
  file: string;
}

const STATE_DIR = ".myrqen";
const TEAM_FILE = "project.json";
const LOCAL_FILE = "local.json";
const GIT_EXCLUDE_RULE = ".myrqen/local.json";

export function bindingPaths(repoRoot: string): { dir: string; team: string; local: string } {
  const dir = path.join(repoRoot, STATE_DIR);
  return { dir, team: path.join(dir, TEAM_FILE), local: path.join(dir, LOCAL_FILE) };
}

async function readJson(file: string): Promise<unknown | null> {
  try {
    return JSON.parse(await fs.readFile(file, "utf8")) as unknown;
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return null;
    throw new Error(`Could not read ${file}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * A committed team binding is authoritative. A local personal file never
 * silently overrides it, and a missing local file never silently falls back to
 * a team workspace.
 */
export async function resolveRepositoryBinding(repoRoot: string): Promise<ResolvedBinding | null> {
  const paths = bindingPaths(repoRoot);

  const team = await readJson(paths.team);
  if (team) {
    const value = team as TeamBinding;
    if (value.version !== 1 || value.kind !== "team" || !value.workspaceId || !value.projectId) {
      throw new Error(
        `${paths.team} is not a valid ${BRAND.displayName} team binding. Fix or remove it; ${BRAND.displayName} will not guess a workspace.`
      );
    }
    return {
      source: "team_committed",
      workspaceKind: "team",
      workspaceId: value.workspaceId,
      projectId: value.projectId,
      file: paths.team
    };
  }

  const local = await readJson(paths.local);
  if (local) {
    const value = local as PersonalBinding;
    if (value.version !== 1 || value.kind !== "personal" || !value.workspaceId || !value.projectId) {
      throw new Error(`${paths.local} is not a valid ${BRAND.displayName} personal binding. Remove it and rebind.`);
    }
    const resolved: ResolvedBinding = {
      source: "personal_local",
      workspaceKind: "personal",
      workspaceId: value.workspaceId,
      projectId: value.projectId,
      file: paths.local
    };
    if (value.workspaceName) resolved.workspaceName = value.workspaceName;
    if (value.projectName) resolved.projectName = value.projectName;
    return resolved;
  }

  return null;
}

export async function writePersonalBinding(
  repoRoot: string,
  binding: Omit<PersonalBinding, "version" | "kind">
): Promise<string> {
  const paths = bindingPaths(repoRoot);
  await fs.mkdir(paths.dir, { recursive: true });
  const payload: PersonalBinding = { version: 1, kind: "personal", ...binding };
  await fs.writeFile(paths.local, `${JSON.stringify(payload, null, 2)}\n`, { mode: 0o600 });
  await excludeLocalBindingFromGit(repoRoot);
  return paths.local;
}

/** The team binding file is safe to commit: identifiers only, never credentials. */
export async function writeTeamBinding(
  repoRoot: string,
  binding: Omit<TeamBinding, "version" | "kind">
): Promise<string> {
  const paths = bindingPaths(repoRoot);
  await fs.mkdir(paths.dir, { recursive: true });
  const payload: TeamBinding = { version: 1, kind: "team", ...binding };
  await fs.writeFile(paths.team, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
  return paths.team;
}

export async function detachBinding(repoRoot: string, which: "personal" | "team" | "both"): Promise<string[]> {
  const paths = bindingPaths(repoRoot);
  const removed: string[] = [];
  const targets = which === "both" ? [paths.local, paths.team] : which === "team" ? [paths.team] : [paths.local];
  for (const target of targets) {
    try {
      await fs.unlink(target);
      removed.push(target);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  }
  return removed;
}

async function excludeLocalBindingFromGit(repoRoot: string): Promise<void> {
  const exclude = path.join(repoRoot, ".git", "info", "exclude");
  try {
    await fs.access(path.join(repoRoot, ".git"));
  } catch {
    // Non-git directories are valid. Personal state stays local by convention.
    return;
  }
  try {
    await fs.mkdir(path.dirname(exclude), { recursive: true });
    let current = "";
    try {
      current = await fs.readFile(exclude, "utf8");
    } catch {
      current = "";
    }
    if (current.split(/\r?\n/).includes(GIT_EXCLUDE_RULE)) return;
    const prefix = current.length > 0 && !current.endsWith("\n") ? "\n" : "";
    await fs.appendFile(exclude, `${prefix}${GIT_EXCLUDE_RULE}\n`);
  } catch {
    // Failing to write the exclude rule must not block a scan.
  }
}

export interface BindingChoiceContext {
  workspaces: Array<{ id: string; name: string; kind: WorkspaceKind }>;
  repositoryHasTeamBinding: boolean;
}

/**
 * Interaction policy: keep it short when there is one sensible option, ask
 * explicitly when there are several. Never infer team membership from a name.
 */
export function bindingInteraction(context: BindingChoiceContext): {
  mode: "already_bound" | "single_option" | "explicit_choice";
  options: BindingChoiceContext["workspaces"];
} {
  if (context.repositoryHasTeamBinding) return { mode: "already_bound", options: [] };
  if (context.workspaces.length <= 1) return { mode: "single_option", options: context.workspaces };
  return { mode: "explicit_choice", options: context.workspaces };
}
