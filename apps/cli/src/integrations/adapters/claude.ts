import fs from "node:fs/promises";
import path from "node:path";
import { BRAND, SKILL_BUNDLE_VERSION } from "@myrqen/brand";
import {
  PAYLOAD_VERSION,
  SKILL_MARKER_FILE,
  directoryExists,
  displayPath,
  findManagedRegions,
  mergeManagedRegion,
  pathExists,
  readIfPresent,
  removeManagedRegion,
  type MarkerStyle
} from "../managed.js";
import {
  absent,
  applicationInstalled,
  configDirectorySignal,
  projectFileSignal,
  verdict,
  whichExecutable
} from "../detect.js";
import { probeVersion } from "../probe.js";
import { pointerPayload, provenanceLine } from "../payload.js";
import type {
  AdapterContext,
  AgentAdapter,
  CommandProbe,
  DetectionSignal,
  InstallPlan,
  InstalledIntegration,
  PlannedWrite,
  Scope,
  ValidationResult
} from "../types.js";

/**
 * Claude Code, and the cross-agent `AGENTS.md` convention.
 *
 * These two live together because they are the two ends of the same decision.
 * Claude Code has a real on-demand primitive — Agent Skills — so it gets the
 * whole method in a skill that loads only when the user asks for a security
 * assessment, plus twenty-five lines in `CLAUDE.md` whose only job is to make
 * the agent reach for that skill at the right moment. `AGENTS.md` has no
 * on-demand primitive at all, so it gets the pointer and nothing else.
 *
 * Verified 2026-08-20 against:
 *   - https://code.claude.com/docs/en/skills  (skill layout and frontmatter)
 *   - https://code.claude.com/docs/en/memory  (CLAUDE.md discovery, ~/.claude/CLAUDE.md)
 *   - https://code.claude.com/docs/en/setup   (CLAUDE_CONFIG_DIR)
 *   - https://agents.md/                      (AGENTS.md is repository-root Markdown)
 *
 * Note for a future maintainer: Claude Code does **not** read `AGENTS.md`. The
 * two adapters below overlap in file format and in nothing else, and installing
 * one is never a substitute for installing the other.
 */

/** Markdown takes HTML comments; a `#` marker would render as a heading. */
const MARKER: MarkerStyle = "html";

const PLATFORMS: readonly NodeJS.Platform[] = Object.freeze(["darwin", "linux", "win32"]);

/* ---------- shared helpers ---------- */

/**
 * Where Claude Code keeps user-scoped configuration.
 *
 * `CLAUDE_CONFIG_DIR` relocates the whole directory, skills and user memory
 * together. Honouring it is not a nicety: on a machine that sets it, writing to
 * a hard-coded `~/.claude` installs a skill into a directory Claude Code never
 * reads, and the user is left with an integration that silently does nothing.
 */
function claudeConfigDirectory(context: AdapterContext): string {
  const override = context.env.CLAUDE_CONFIG_DIR?.trim();
  return override ? path.resolve(override) : path.join(context.home, ".claude");
}

interface ClaudeLayout {
  /** Directory holding one folder per skill. */
  skillsDirectory: string;
  /**
   * Instruction files Claude Code reads at this scope, in the order Myrqen
   * prefers them. Both project locations are documented and equivalent, so the
   * one the project already uses wins over the one Myrqen would have picked.
   */
  pointerCandidates: string[];
}

function claudeLayout(context: AdapterContext, scope: Scope): ClaudeLayout {
  if (scope === "project") {
    return {
      skillsDirectory: path.join(context.repoRoot, ".claude", "skills"),
      pointerCandidates: [path.join(context.repoRoot, "CLAUDE.md"), path.join(context.repoRoot, ".claude", "CLAUDE.md")]
    };
  }
  const configDirectory = claudeConfigDirectory(context);
  return {
    skillsDirectory: path.join(configDirectory, "skills"),
    pointerCandidates: [path.join(configDirectory, "CLAUDE.md")]
  };
}

function show(context: AdapterContext, target: string): string {
  return displayPath(target, context.repoRoot, context.home);
}

/** The first candidate that already exists, otherwise the preferred one. */
async function resolvePointerTarget(candidates: string[]): Promise<string> {
  for (const candidate of candidates) {
    if (await pathExists(candidate)) return candidate;
  }
  return candidates[0]!;
}

/** Every candidate that currently carries a Myrqen-managed region. */
async function pointerFilesWithRegion(candidates: string[]): Promise<Array<{ path: string; text: string }>> {
  const found: Array<{ path: string; text: string }> = [];
  for (const candidate of candidates) {
    const text = await readIfPresent(candidate);
    if (text === null) continue;
    if (findManagedRegions(text, MARKER).length > 0) found.push({ path: candidate, text });
  }
  return found;
}

/**
 * Plan one merge into a shared instruction file.
 *
 * Every branch here except `blocked` keeps the user's own instructions byte for
 * byte; `mergeManagedRegion` is what guarantees that, and this function's only
 * job is to translate its answer into the vocabulary the plan renderer speaks.
 */
async function planPointerWrite(context: AdapterContext, target: string, body: string): Promise<PlannedWrite> {
  const existing = await readIfPresent(target);
  const merged = mergeManagedRegion(existing, body, MARKER);
  const displayed = show(context, target);

  if (merged.action === "conflicted") {
    // Two managed regions means a bad merge or a hand-edit. Rewriting one of
    // them would quietly delete whichever the user meant to keep.
    return {
      path: target,
      displayPath: displayed,
      action: "blocked",
      preservesExistingContent: true,
      reason: `this file holds more than one ${BRAND.displayName} region; delete the extra one, then run "${BRAND.cliName} link" again`
    };
  }

  if (merged.action === "unchanged") {
    return {
      path: target,
      displayPath: displayed,
      action: "unchanged",
      preservesExistingContent: merged.preservesExistingContent
    };
  }

  return {
    path: target,
    displayPath: displayed,
    action: merged.action,
    contents: merged.contents,
    preservesExistingContent: merged.preservesExistingContent
  };
}

/** Plan the removal of a managed region, or nothing at all if there is none. */
async function planPointerRemoval(context: AdapterContext, target: string): Promise<PlannedWrite | null> {
  const existing = await readIfPresent(target);
  if (existing === null) return null;
  const removal = removeManagedRegion(existing, MARKER);
  if (!removal.removed) return null;

  const displayed = show(context, target);
  if (removal.empty) {
    // Nothing but Myrqen's region was in the file, so Myrqen created it and an
    // empty `CLAUDE.md` left behind would be litter with a meaning of its own.
    return { path: target, displayPath: displayed, action: "remove", preservesExistingContent: false };
  }
  return {
    path: target,
    displayPath: displayed,
    action: "remove",
    contents: removal.contents,
    preservesExistingContent: true
  };
}

/**
 * Every file in the portable skill bundle, contents included, in the order a
 * reader expects: `SKILL.md` first, then each reference directory.
 *
 * The bundle is Markdown throughout, and `PlannedWrite.contents` is a string,
 * so the plan format itself cannot carry a binary asset. If the bundle ever
 * grows one, this is the function that has to change.
 */
async function readBundle(root: string): Promise<Array<{ relative: string; contents: string }>> {
  const collected: Array<{ relative: string; contents: string }> = [];

  const walk = async (directory: string, prefix: string): Promise<void> => {
    const entries = (await fs.readdir(directory, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (!entry.isFile() || entry.name === SKILL_MARKER_FILE) continue;
      collected.push({
        relative: path.posix.join(prefix, entry.name),
        contents: await fs.readFile(path.join(directory, entry.name), "utf8")
      });
    }
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      await walk(path.join(directory, entry.name), path.posix.join(prefix, entry.name));
    }
  };

  await walk(root, "");
  return collected;
}

/**
 * What Myrqen records beside an installed bundle.
 *
 * Deliberately free of a timestamp: a value that changes on every run would make
 * the marker differ from itself and turn a re-plan of an untouched install into
 * a permanent "update" — the plan would never once say "unchanged", which is the
 * property the whole install flow is built on.
 */
function skillMarkerContents(): string {
  return `${JSON.stringify({ managedBy: BRAND.displayName, version: SKILL_BUNDLE_VERSION }, null, 2)}\n`;
}

function fileWrite(context: AdapterContext, target: string, contents: string, current: string | null): PlannedWrite {
  const same = current === contents;
  return {
    path: target,
    displayPath: show(context, target),
    action: current === null ? "create" : same ? "unchanged" : "update",
    ...(same ? {} : { contents }),
    // A skill file is a file Myrqen owns outright. Nothing of the user's is in it.
    preservesExistingContent: false
  };
}

/**
 * Plan the skill bundle as ordinary file writes.
 *
 * Planning has to be pure, so nothing here writes: the user sees every path
 * before a byte lands, and the applier in `../apply.ts` is the only thing in
 * this layer allowed to touch the disk — which is also what makes a
 * half-finished install roll back cleanly. An earlier release installed this
 * same bundle imperatively from `../../install/skill.ts` as well; that second
 * writer is gone, so this plan is now the only description of what a Claude Code
 * skill directory holds.
 */
async function planSkillWrites(context: AdapterContext, skillsDirectory: string): Promise<PlannedWrite[]> {
  const destination = path.join(skillsDirectory, BRAND.skillId);
  const displayed = show(context, destination);

  if (!context.skillSource) {
    return [
      {
        path: destination,
        displayPath: displayed,
        action: "blocked",
        preservesExistingContent: false,
        reason: "the portable skill bundle that ships with this CLI could not be located"
      }
    ];
  }

  const markerPath = path.join(destination, SKILL_MARKER_FILE);
  if ((await directoryExists(destination)) && !(await pathExists(markerPath))) {
    // Someone else's skill happens to have this name. The imperative installer
    // renames it out of the way first; a plan can only describe writes, so the
    // honest thing is to stop rather than to overwrite it file by file.
    return [
      {
        path: destination,
        displayPath: displayed,
        action: "blocked",
        preservesExistingContent: true,
        reason: `a skill directory ${BRAND.displayName} did not write is already here; move it aside, then run "${BRAND.cliName} link" again`
      }
    ];
  }

  const writes: PlannedWrite[] = [];
  for (const file of await readBundle(context.skillSource)) {
    const target = path.join(destination, ...file.relative.split("/"));
    writes.push(fileWrite(context, target, file.contents, await readIfPresent(target)));
  }
  writes.push(fileWrite(context, markerPath, skillMarkerContents(), await readIfPresent(markerPath)));
  return writes;
}

/**
 * Plan the bundle's removal.
 *
 * Reversed, so the deepest files go first: the applier deletes a directory only
 * once it is empty, and removing `references/*` before `SKILL.md` before the
 * marker is what lets `.claude/skills/myrqen` disappear instead of lingering as
 * an empty shell. The marker goes last for the same reason it exists — while it
 * is on disk, the directory is still recognisably Myrqen's.
 */
async function planSkillRemoval(context: AdapterContext, skillsDirectory: string): Promise<PlannedWrite[]> {
  const destination = path.join(skillsDirectory, BRAND.skillId);
  const markerPath = path.join(destination, SKILL_MARKER_FILE);
  if (!(await pathExists(markerPath))) return [];

  const present: string[] = [];
  const walk = async (directory: string): Promise<void> => {
    const entries = (await fs.readdir(directory, { withFileTypes: true }).catch(() => [])).sort((a, b) =>
      a.name.localeCompare(b.name)
    );
    for (const entry of entries) {
      const full = path.join(directory, entry.name);
      if (entry.isDirectory()) await walk(full);
      else if (entry.isFile() && full !== markerPath) present.push(full);
    }
  };
  await walk(destination);

  return [...present.reverse(), markerPath].map((target) => ({
    path: target,
    displayPath: show(context, target),
    action: "remove" as const,
    preservesExistingContent: false
  }));
}

/* ---------- Claude Code ---------- */

/** The pointer Claude Code gets: short, and pointed at the skill by name. */
function claudePointerBody(): string {
  return `${pointerPayload({ skillAvailable: true, slashCommand: BRAND.skillId })}\n\n${provenanceLine()}`;
}

/**
 * `claude --version` prints the version and exits.
 *
 * Verified 2026-08-20 against a clean install: no configuration is created, no
 * network call is made, and the process ends without waiting for anything.
 */
const CLAUDE_CLI: CommandProbe = { command: "claude", flag: "--version" };

export const claudeCodeAdapter: AgentAdapter = {
  id: "claude-code",
  displayName: "Claude Code",
  documentation: "https://code.claude.com/docs/en/skills",
  primitive: "skill",
  platforms: PLATFORMS,
  probes: [CLAUDE_CLI],

  async detect(context) {
    const signals: DetectionSignal[] = [];
    let version: string | undefined;

    const executable = await whichExecutable("claude", context);
    if (executable) {
      // The path answers the question. Everything after this line is decoration
      // on a verdict that already stands.
      signals.push({ kind: "executable", detail: `claude at ${show(context, executable)}` });
      version = await probeVersion(context, CLAUDE_CLI, executable, signals);
    }

    // The desktop application is a weaker claim than the CLI — someone can have
    // Claude without Claude Code. It stays in the list because the plan is
    // printed and confirmed before anything is written, so a false positive
    // costs the user one keystroke rather than a file they did not want.
    const application = await applicationInstalled(["Claude"], context);
    if (application) signals.push({ kind: "application", detail: `Claude application at ${application}` });

    const override = context.env.CLAUDE_CONFIG_DIR?.trim();
    if (override) {
      signals.push({ kind: "environment_variable", detail: `CLAUDE_CONFIG_DIR is set to ${override}` });
    }

    const configDirectory = await configDirectorySignal(
      path.relative(context.home, claudeConfigDirectory(context)) || ".claude",
      context,
      "Claude Code configuration"
    );
    if (configDirectory) signals.push(configDirectory);

    // Existence only. `~/.claude.json` holds a session history and account
    // state, and detection has no business opening it.
    if (await pathExists(path.join(context.home, ".claude.json"))) {
      signals.push({ kind: "config_file", detail: "~/.claude.json" });
    }

    const projectDirectory = await projectFileSignal(".claude", context);
    if (projectDirectory) signals.push(projectDirectory);

    if (signals.length === 0) return absent;
    return verdict(signals, version);
  },

  supportedScopes() {
    // Both are documented: `.claude/skills` and `CLAUDE.md` in the project,
    // `~/.claude/skills` and `~/.claude/CLAUDE.md` for the user.
    return ["project", "global"];
  },

  async createInstallPlan(context, scope) {
    const layout = claudeLayout(context, scope);
    const writes = await planSkillWrites(context, layout.skillsDirectory);

    const pointerTarget = await resolvePointerTarget(layout.pointerCandidates);
    const pointer = await planPointerWrite(context, pointerTarget, claudePointerBody());
    writes.push(pointer);

    const notes = [
      `Invoke with /${BRAND.skillId} in Claude Code, or "${BRAND.cliName} auto" from any shell.`,
      `The method loads only when the skill runs. ${pointer.displayPath} carries a short pointer to it, not the method itself.`
    ];
    if (scope === "global") {
      notes.push("Installed for every project on this machine. Link a project too if you want the pointer in its own CLAUDE.md.");
    }

    return { adapterId: this.id, displayName: this.displayName, scope, writes, notes };
  },

  async installed(context) {
    const found: InstalledIntegration[] = [];

    for (const scope of ["project", "global"] as const) {
      const layout = claudeLayout(context, scope);
      const markerPath = path.join(layout.skillsDirectory, BRAND.skillId, SKILL_MARKER_FILE);
      const marker = await readIfPresent(markerPath);
      const regions = await pointerFilesWithRegion(layout.pointerCandidates);
      if (marker === null && regions.length === 0) continue;

      // The pointer is what tells the agent Myrqen exists, so it names the
      // integration when it is present; the skill directory names it otherwise.
      const primary = regions[0];
      const anchor = primary ? primary.path : path.join(layout.skillsDirectory, BRAND.skillId, "SKILL.md");

      let payloadVersion = PAYLOAD_VERSION;
      if (primary) {
        payloadVersion = findManagedRegions(primary.text, MARKER)[0]?.version ?? PAYLOAD_VERSION;
      } else if (marker !== null) {
        payloadVersion = readMarkerVersion(marker);
      }

      found.push({
        adapterId: this.id,
        scope,
        path: anchor,
        displayPath: show(context, anchor),
        payloadVersion,
        sharedFile: primary ? !removeManagedRegion(primary.text, MARKER).empty : false
      });
    }

    return found;
  },

  async validate(context, integration) {
    const layout = claudeLayout(context, integration.scope);
    const skill = await skillHealth(context, layout.skillsDirectory);
    const pointer = await pointerHealth(layout.pointerCandidates, claudePointerBody());
    return combine(
      [
        { label: "the skill bundle", state: skill },
        { label: `the pointer in ${integration.displayPath}`, state: pointer }
      ],
      `Run "${BRAND.cliName} link --agent claude-code" to bring it up to date.`
    );
  },

  async createUninstallPlan(context, scope) {
    const layout = claudeLayout(context, scope);
    const writes = await planSkillRemoval(context, layout.skillsDirectory);
    for (const candidate of layout.pointerCandidates) {
      const removal = await planPointerRemoval(context, candidate);
      if (removal) writes.push(removal);
    }
    return {
      adapterId: this.id,
      displayName: this.displayName,
      scope,
      writes,
      notes:
        writes.length === 0
          ? [`Nothing ${BRAND.displayName} wrote is left at this scope.`]
          : ["Instructions you wrote yourself in CLAUDE.md are kept exactly as they are."]
    };
  }
};

function readMarkerVersion(marker: string): string {
  try {
    const parsed = JSON.parse(marker) as { version?: unknown };
    return typeof parsed.version === "string" ? parsed.version : PAYLOAD_VERSION;
  } catch {
    return PAYLOAD_VERSION;
  }
}

/* ---------- shared AGENTS.md ---------- */

/**
 * AGENTS.md gets the pointer with no slash command in it.
 *
 * A dozen different agents read this one file and none of them share an
 * invocation, so naming one tool's syntax here would be wrong for every reader
 * but that tool. `myrqen auto` works from any of them that can run a shell.
 */
function agentsMdBody(): string {
  return `${pointerPayload({ skillAvailable: false })}\n\n${provenanceLine()}`;
}

export const agentsMdAdapter: AgentAdapter = {
  id: "agents-md",
  displayName: "Shared AGENTS.md",
  documentation: "https://agents.md/",
  primitive: "instructions_file",
  platforms: PLATFORMS,

  /**
   * There is no program to look for.
   *
   * `AGENTS.md` is a convention, so the only truthful signal is the file
   * itself, and `project_only` is exactly what that means: this repository is
   * set up for agents that read it, and nothing was learned about this machine.
   * The installer still offers it by hand, because wanting the file before any
   * agent reads it is a perfectly ordinary thing to want.
   */
  async detect(context) {
    const signal = await projectFileSignal("AGENTS.md", context);
    return signal ? verdict([signal]) : absent;
  },

  supportedScopes() {
    // agents.md documents a repository-root file and no user-level location.
    // Individual tools invent their own (`~/.codex/AGENTS.md`,
    // `~/.config/opencode/AGENTS.md`), and those belong to those tools'
    // adapters — writing them from here would be guessing on the convention's
    // behalf.
    return ["project"];
  },

  async createInstallPlan(context, scope) {
    const target = path.join(context.repoRoot, "AGENTS.md");
    if (scope === "global") {
      return {
        adapterId: this.id,
        displayName: this.displayName,
        scope,
        writes: [
          {
            path: target,
            displayPath: "AGENTS.md",
            action: "blocked",
            preservesExistingContent: false,
            reason: "the AGENTS.md convention documents no user-level location, only a file at the repository root"
          }
        ],
        notes: [`Install it for this project instead: "${BRAND.cliName} link --agent agents-md --scope project".`]
      };
    }

    return {
      adapterId: this.id,
      displayName: this.displayName,
      scope,
      writes: [await planPointerWrite(context, target, agentsMdBody())],
      notes: [
        "AGENTS.md is a convention, not a program, and support for it is uneven.",
        `Claude Code and Aider do not read it at all — link those separately. Agents that do read it will run "${BRAND.cliName} auto".`
      ]
    };
  },

  async installed(context) {
    const target = path.join(context.repoRoot, "AGENTS.md");
    const text = await readIfPresent(target);
    if (text === null) return [];
    const regions = findManagedRegions(text, MARKER);
    if (regions.length === 0) return [];

    return [
      {
        adapterId: this.id,
        scope: "project",
        path: target,
        displayPath: show(context, target),
        payloadVersion: regions[0]?.version ?? PAYLOAD_VERSION,
        sharedFile: !removeManagedRegion(text, MARKER).empty
      }
    ];
  },

  async validate(context) {
    const target = path.join(context.repoRoot, "AGENTS.md");
    const state = await pointerHealth([target], agentsMdBody());
    return combine(
      [{ label: "the AGENTS.md region", state }],
      `Run "${BRAND.cliName} link --agent agents-md" to bring it up to date.`
    );
  },

  async createUninstallPlan(context, scope) {
    const target = path.join(context.repoRoot, "AGENTS.md");
    const removal = await planPointerRemoval(context, target);
    return {
      adapterId: this.id,
      displayName: this.displayName,
      scope,
      writes: removal ? [removal] : [],
      notes: removal
        ? ["Everything else in AGENTS.md is kept exactly as it is."]
        : [`Nothing ${BRAND.displayName} wrote is left in AGENTS.md.`]
    };
  }
};

/* ---------- health ---------- */

type ArtifactState = "current" | "stale" | "missing" | "conflicted";

/** Is the installed bundle the one this CLI ships? */
async function skillHealth(context: AdapterContext, skillsDirectory: string): Promise<ArtifactState> {
  const destination = path.join(skillsDirectory, BRAND.skillId);
  const marker = await readIfPresent(path.join(destination, SKILL_MARKER_FILE));
  if (marker === null) return "missing";
  if (readMarkerVersion(marker) !== SKILL_BUNDLE_VERSION) return "stale";
  if (!context.skillSource) return "current";

  for (const file of await readBundle(context.skillSource)) {
    const target = path.join(destination, ...file.relative.split("/"));
    if ((await readIfPresent(target)) !== file.contents) return "stale";
  }
  return "current";
}

/**
 * Is the managed region the region this CLI would write?
 *
 * Asked by planning the merge and reading the verdict back, rather than by
 * rebuilding the marker syntax here. One implementation of "what does a current
 * region look like" means validation can never disagree with installation.
 */
async function pointerHealth(candidates: string[], body: string): Promise<ArtifactState> {
  const present = await pointerFilesWithRegion(candidates);
  if (present.length === 0) return "missing";
  if (present.length > 1) return "conflicted";

  const merged = mergeManagedRegion(present[0]!.text, body, MARKER);
  if (merged.action === "conflicted") return "conflicted";
  return merged.action === "unchanged" ? "current" : "stale";
}

function combine(parts: Array<{ label: string; state: ArtifactState }>, remedy: string): ValidationResult {
  const conflicted = parts.filter((part) => part.state === "conflicted");
  if (conflicted.length > 0) {
    return {
      health: "conflicted",
      detail: `${sentence(conflicted.map((part) => part.label))} could not be read as a single ${BRAND.displayName} region.`,
      remedy: `Remove the duplicate region by hand, then run "${BRAND.cliName} link".`
    };
  }

  const missing = parts.filter((part) => part.state === "missing");
  if (missing.length === parts.length) {
    return { health: "missing", detail: `Nothing ${BRAND.displayName} wrote is on disk for this agent.`, remedy };
  }

  const behind = parts.filter((part) => part.state !== "current");
  if (behind.length > 0) {
    return {
      health: "stale",
      detail: `${sentence(behind.map((part) => part.label))} is older than this version of ${BRAND.displayName}.`,
      remedy
    };
  }

  return { health: "healthy", detail: `Installed and current (payload v${PAYLOAD_VERSION}).` };
}

/** "a", "a and b", "a, b and c" — so the detail line reads like a sentence. */
function sentence(labels: string[]): string {
  if (labels.length <= 1) return capitalise(labels[0] ?? "It");
  return capitalise(`${labels.slice(0, -1).join(", ")} and ${labels[labels.length - 1]}`);
}

function capitalise(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}
