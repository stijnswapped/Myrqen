import fs from "node:fs/promises";
import path from "node:path";
import { BRAND } from "@myrqen/brand";
import type {
  AgentMetadata,
  AuthorizedExternalTarget,
  CoverageArea,
  EffortProfile,
  EffortRequested,
  EffortResolved,
  Finding,
  HostEnvironment,
  LocalCloudState,
  PhaseRecord,
  ScanPhase,
  ScanState,
  StackSummary,
  SyncQuota,
  TokenUsage,
  WorkspaceKind
} from "@myrqen/contracts";
import { extractEnvSecretValues } from "@myrqen/policy";
import { currentSessionPointer, sessionDirectory, stateDirectory } from "../config/paths.js";

/** A sync decision that the CLI could not ask for because there was no TTY. */
export type LocalCloudStateExtended = LocalCloudState | "decision_required";

export interface ActionLogEntry {
  at: string;
  intent: string;
  allowed: boolean;
  violations?: string[];
}

export interface SessionState {
  version: 1;
  localReportId: string;
  repoRoot: string;
  createdAt: string;
  startedAt: string;
  finishedAt?: string;
  state: ScanState;
  effort: {
    requested: EffortRequested;
    resolved: EffortResolved;
    profile: EffortProfile;
    rationale: string[];
  };
  project: {
    name: string;
    workspaceKind: WorkspaceKind;
    workspaceName?: string;
    workspaceId?: string;
    projectId?: string;
    bindingSource: "team_committed" | "personal_local" | "unbound";
  };
  agent: AgentMetadata;
  host: HostEnvironment;
  stack: StackSummary;
  scope: {
    localTargets: string[];
    authorizedExternalTargets: AuthorizedExternalTarget[];
    deniedExternalTargets: string[];
    pendingExternalCandidates: string[];
    /** Suggested only by content that also tried to instruct the scanner. */
    injectionSuggestedOrigins: string[];
  };
  /**
   * Paths whose values are re-read on demand for redaction. Raw secret values are
   * never written to session state.
   */
  secretSources: string[];
  phases: PhaseRecord[];
  findings: Finding[];
  coverage: string[];
  coverageAreas: CoverageArea[];
  limitations: string[];
  candidateCount: number;
  duplicateCount: number;
  nextFindingSeq: number;
  tokenUsage: TokenUsage;
  cloud: {
    state: LocalCloudStateExtended;
    reportId?: string;
    reportUrl?: string;
    expiresAt?: string;
    reason?: string;
    quota?: SyncQuota;
    lastError?: string;
  };
  injectionObservations: Array<{ file: string; id: string; excerpt: string }>;
  actionLog: ActionLogEntry[];
  routeSamples: string[];
}

function sessionFile(repoRoot: string, localReportId: string): string {
  return path.join(sessionDirectory(repoRoot, localReportId), "session.json");
}

export async function saveSession(state: SessionState): Promise<void> {
  const directory = sessionDirectory(state.repoRoot, state.localReportId);
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  await fs.writeFile(sessionFile(state.repoRoot, state.localReportId), `${JSON.stringify(state, null, 2)}\n`, {
    mode: 0o600
  });
}

export async function setCurrentSession(repoRoot: string, localReportId: string): Promise<void> {
  await fs.mkdir(stateDirectory(repoRoot), { recursive: true });
  await fs.writeFile(currentSessionPointer(repoRoot), `${localReportId}\n`, { mode: 0o600 });
  await excludeStateFromGit(repoRoot);
}

export async function readCurrentSessionId(repoRoot: string): Promise<string | null> {
  try {
    const value = (await fs.readFile(currentSessionPointer(repoRoot), "utf8")).trim();
    return value.length > 0 ? value : null;
  } catch {
    return null;
  }
}

export async function loadSession(repoRoot: string, localReportId?: string): Promise<SessionState | null> {
  const id = localReportId ?? (await readCurrentSessionId(repoRoot));
  if (!id) return null;
  try {
    return JSON.parse(await fs.readFile(sessionFile(repoRoot, id), "utf8")) as SessionState;
  } catch {
    return null;
  }
}

export async function requireSession(repoRoot: string, localReportId?: string): Promise<SessionState> {
  const state = await loadSession(repoRoot, localReportId);
  if (!state) {
    throw new Error(
      `No active ${BRAND.displayName} session in this repository. Start one with "${BRAND.cliName} session start --effort auto".`
    );
  }
  return state;
}

export async function listSessions(repoRoot: string): Promise<SessionState[]> {
  const directory = path.join(stateDirectory(repoRoot), "sessions");
  let entries: string[];
  try {
    entries = await fs.readdir(directory);
  } catch {
    return [];
  }
  const sessions: SessionState[] = [];
  for (const entry of entries) {
    const state = await loadSession(repoRoot, entry);
    if (state) sessions.push(state);
  }
  return sessions.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

/** Local scan state is never committed. */
export async function excludeStateFromGit(repoRoot: string): Promise<void> {
  const excludeFile = path.join(repoRoot, ".git", "info", "exclude");
  const rules = [".myrqen/local.json", ".myrqen/sessions/", ".myrqen/reports/", ".myrqen/current-session"];
  try {
    await fs.access(path.join(repoRoot, ".git"));
  } catch {
    return;
  }
  try {
    await fs.mkdir(path.dirname(excludeFile), { recursive: true });
    let current = "";
    try {
      current = await fs.readFile(excludeFile, "utf8");
    } catch {
      current = "";
    }
    const existing = new Set(current.split(/\r?\n/));
    const missing = rules.filter((rule) => !existing.has(rule));
    if (missing.length === 0) return;
    const prefix = current.length > 0 && !current.endsWith("\n") ? "\n" : "";
    await fs.appendFile(excludeFile, `${prefix}${missing.join("\n")}\n`);
  } catch {
    // Failing to write a git exclude rule must never block a scan.
  }
}

/**
 * Secret values are re-read from disk when needed and never persisted into
 * session state, reports, or logs.
 */
export async function loadKnownSecrets(state: SessionState): Promise<string[]> {
  const values = new Set<string>();
  for (const relative of state.secretSources) {
    try {
      const contents = await fs.readFile(path.join(state.repoRoot, relative), "utf8");
      for (const value of extractEnvSecretValues(contents)) values.add(value);
    } catch {
      // The file may have been removed since discovery.
    }
  }
  return [...values];
}

export function markPhase(state: SessionState, phase: ScanPhase, next: "running" | "complete", at = new Date()): PhaseRecord {
  const existing = state.phases.find((record) => record.phase === phase);
  const iso = at.toISOString();
  if (!existing) {
    const record: PhaseRecord = { phase, state: next, startedAt: iso };
    if (next === "complete") {
      record.completedAt = iso;
      record.durationMs = 0;
    }
    state.phases.push(record);
    return record;
  }
  existing.state = next;
  if (next === "running") existing.startedAt = iso;
  if (next === "complete") {
    existing.completedAt = iso;
    if (existing.startedAt) existing.durationMs = at.getTime() - new Date(existing.startedAt).getTime();
  }
  return existing;
}

export function nextFindingId(state: SessionState): string {
  state.nextFindingSeq += 1;
  return `MYR-${String(state.nextFindingSeq).padStart(3, "0")}`;
}

export function elapsedMs(state: SessionState, at = new Date()): number {
  return Math.max(0, at.getTime() - new Date(state.startedAt).getTime());
}

export function budgetExceeded(state: SessionState, at = new Date()): boolean {
  return elapsedMs(state, at) > state.effort.profile.wallClockBudgetMs;
}
