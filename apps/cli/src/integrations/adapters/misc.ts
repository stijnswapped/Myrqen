import fs from "node:fs/promises";
import path from "node:path";
import { BRAND, SKILL_BUNDLE_VERSION } from "@myrqen/brand";
import {
  PAYLOAD_VERSION,
  SKILL_MARKER_FILE,
  directoryExists,
  displayPath,
  endMarker,
  findManagedRegions,
  mergeManagedRegion,
  ownedFileHeader,
  pathExists,
  readIfPresent,
  removeManagedRegion,
  type MarkerStyle
} from "../managed.js";
import {
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
  DetectionResult,
  DetectionSignal,
  FileAction,
  InstallPlan,
  InstalledIntegration,
  PlannedWrite,
  Scope,
  ValidationResult
} from "../types.js";

/**
 * Codex CLI, Kiro, Aider, and OpenCode.
 *
 * Four agents grouped here because each one needed a decision none of the
 * others did: Codex resolves its user directory from an environment variable,
 * Kiro requires YAML frontmatter in the literal first bytes of a Markdown file,
 * Aider reads no rules file at all unless its own YAML config points at one, and
 * OpenCode has only a skill. The shared plumbing at the top of this file is what
 * keeps those four differences from becoming four near-duplicate adapters.
 */

const ALL_PLATFORMS: readonly NodeJS.Platform[] = ["darwin", "linux", "win32"];

/* ---------- shared plumbing ---------- */

function planned(
  context: AdapterContext,
  target: string,
  action: FileAction,
  options: { contents?: string; preservesExistingContent?: boolean; reason?: string } = {}
): PlannedWrite {
  return {
    path: target,
    displayPath: displayPath(target, context.repoRoot, context.home),
    action,
    ...(options.contents === undefined ? {} : { contents: options.contents }),
    preservesExistingContent: options.preservesExistingContent ?? false,
    ...(options.reason === undefined ? {} : { reason: options.reason })
  };
}

/** The short payload, stamped so `status` and `doctor` can read the version back. */
function pointerBody(skillAvailable: boolean, slashCommand?: string): string {
  const payload = pointerPayload(
    slashCommand === undefined ? { skillAvailable } : { skillAvailable, slashCommand }
  );
  return `${payload}\n\n${provenanceLine()}`;
}

/**
 * A file Myrqen writes in full.
 *
 * The whole body sits inside one managed region even though nothing else shares
 * the file, because that region is how `installed()` recognises its own work
 * later. Without it, a file Myrqen wrote and a file the user happened to name
 * the same thing are indistinguishable, and uninstall would have to guess.
 *
 * `header` exists for formats that demand something before the marker — Kiro's
 * steering frontmatter has to be the first bytes of the file.
 */
function ownedFileContents(style: MarkerStyle, body: string, header = ""): string {
  return `${header}${ownedFileHeader(style)}\n\n${body.trim()}\n${endMarker(style)}\n`;
}

async function planOwnedFile(
  context: AdapterContext,
  target: string,
  contents: string,
  style: MarkerStyle
): Promise<PlannedWrite> {
  const existing = await readIfPresent(target);
  if (existing === null) return planned(context, target, "create", { contents });
  if (existing === contents) return planned(context, target, "unchanged");
  if (findManagedRegions(existing.replace(/\r\n/g, "\n"), style).length > 0) {
    return planned(context, target, "update", { contents });
  }
  return planned(context, target, "blocked", {
    preservesExistingContent: true,
    reason: `a file ${BRAND.displayName} did not write is already here; move it aside and run "${BRAND.cliName} link" again`
  });
}

async function planOwnedFileRemoval(
  context: AdapterContext,
  target: string,
  style: MarkerStyle
): Promise<PlannedWrite | null> {
  const existing = await readIfPresent(target);
  if (existing === null) return null;
  if (findManagedRegions(existing.replace(/\r\n/g, "\n"), style).length === 0) {
    return planned(context, target, "blocked", {
      preservesExistingContent: true,
      reason: `this file no longer carries a ${BRAND.displayName} marker, so it is left alone`
    });
  }
  return planned(context, target, "remove");
}

/** A file the user owns, into which Myrqen merges exactly one marked region. */
async function planMergedRegion(
  context: AdapterContext,
  target: string,
  body: string,
  style: MarkerStyle
): Promise<PlannedWrite> {
  const merged = mergeManagedRegion(await readIfPresent(target), body, style);
  if (merged.action === "conflicted") {
    return planned(context, target, "blocked", {
      preservesExistingContent: true,
      reason: `two ${BRAND.displayName} regions are in this file; remove one and run "${BRAND.cliName} link" again`
    });
  }
  if (merged.action === "unchanged") {
    return planned(context, target, "unchanged", { preservesExistingContent: merged.preservesExistingContent });
  }
  return planned(context, target, merged.action, {
    contents: merged.contents,
    preservesExistingContent: merged.preservesExistingContent
  });
}

async function planMergedRemoval(
  context: AdapterContext,
  target: string,
  style: MarkerStyle
): Promise<PlannedWrite | null> {
  const existing = await readIfPresent(target);
  if (existing === null) return null;
  const removed = removeManagedRegion(existing, style);
  if (!removed.removed) return null;
  // An instructions file with nothing but Myrqen's region left in it is litter,
  // so it goes; anything else is rewritten without the region and keeps every
  // other byte the user put there.
  if (removed.empty) return planned(context, target, "remove");
  return planned(context, target, "remove", { contents: removed.contents, preservesExistingContent: true });
}

/* ---------- skill bundles ---------- */

async function listFiles(directory: string): Promise<string[]> {
  const found: string[] = [];
  const walk = async (current: string, prefix: string): Promise<void> => {
    const entries = (await fs.readdir(current, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const full = path.join(current, entry.name);
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        await walk(full, relative);
        continue;
      }
      if (!entry.isFile()) continue;
      found.push(relative);
    }
  };
  await walk(directory, "");
  return found;
}

function markerVersion(marker: string): string | null {
  try {
    const parsed = JSON.parse(marker) as { version?: unknown };
    return typeof parsed.version === "string" ? parsed.version : null;
  } catch {
    return null;
  }
}

function markerContents(): string {
  return `${JSON.stringify(
    { managedBy: BRAND.displayName, version: SKILL_BUNDLE_VERSION, installedAt: new Date().toISOString() },
    null,
    2
  )}\n`;
}

/**
 * Plan a skill-bundle install without touching the disk.
 *
 * `createInstallPlan` has to compute a plan the user approves *before* anything
 * is written, so the bundle is read here, every file becomes a `PlannedWrite`,
 * and `apply.ts` executes them with a snapshot and a rollback. What lands on
 * disk is the bundle plus the marker file named by `SKILL_MARKER_FILE`, which
 * the Claude Code adapter writes too — one spelling of that name, in
 * `../managed.js`, is what stops the two from disagreeing about whether a skill
 * is installed.
 */
async function planSkillBundle(context: AdapterContext, destination: string): Promise<PlannedWrite[]> {
  const markerPath = path.join(destination, SKILL_MARKER_FILE);

  if (!context.skillSource) {
    return [
      planned(context, path.join(destination, "SKILL.md"), "blocked", {
        reason: `the portable skill bundle that ships with this CLI could not be located; reinstall ${BRAND.cliName}`
      })
    ];
  }

  const managed = await pathExists(markerPath);
  if (!managed && (await directoryExists(destination))) {
    return [
      planned(context, destination, "blocked", {
        preservesExistingContent: true,
        reason: `a skill named "${BRAND.skillId}" that ${BRAND.displayName} did not write is installed here; move it aside and run "${BRAND.cliName} link" again`
      })
    ];
  }

  let bundle: string[];
  try {
    bundle = (await listFiles(context.skillSource)).filter((relative) => relative !== SKILL_MARKER_FILE);
  } catch {
    bundle = [];
  }
  if (bundle.length === 0) {
    return [
      planned(context, path.join(destination, "SKILL.md"), "blocked", {
        reason: `the portable skill bundle at ${context.skillSource} is empty or unreadable`
      })
    ];
  }

  const writes: PlannedWrite[] = [];
  let changed = false;
  for (const relative of bundle) {
    const target = path.join(destination, ...relative.split("/"));
    const contents = await fs.readFile(path.join(context.skillSource, ...relative.split("/")), "utf8");
    const existing = await readIfPresent(target);
    if (existing === contents) {
      writes.push(planned(context, target, "unchanged"));
      continue;
    }
    changed = true;
    writes.push(planned(context, target, existing === null ? "create" : "update", { contents }));
  }

  // A file left behind by an older bundle is removed, because a skill directory
  // that still carries a reference the current method no longer mentions sends
  // the agent to documentation that is no longer true.
  if (managed) {
    const stale = (await listFiles(destination).catch(() => [])).filter(
      (relative) => relative !== SKILL_MARKER_FILE && !bundle.includes(relative)
    );
    for (const relative of stale) {
      changed = true;
      writes.push(planned(context, path.join(destination, ...relative.split("/")), "remove"));
    }
  }

  const existingMarker = await readIfPresent(markerPath);
  const markerCurrent = existingMarker !== null && markerVersion(existingMarker) === SKILL_BUNDLE_VERSION;
  if (!changed && markerCurrent) {
    // The marker records an install time, so rewriting it on an unchanged run
    // would make every `myrqen link` report a change that is not one.
    writes.push(planned(context, markerPath, "unchanged"));
  } else {
    writes.push(planned(context, markerPath, existingMarker === null ? "create" : "update", { contents: markerContents() }));
  }
  return writes;
}

async function planSkillBundleRemoval(context: AdapterContext, destination: string): Promise<PlannedWrite[]> {
  if (!(await pathExists(path.join(destination, SKILL_MARKER_FILE)))) return [];
  const files = await listFiles(destination).catch(() => []);
  return files.map((relative) => planned(context, path.join(destination, ...relative.split("/")), "remove"));
}

async function skillIntegration(
  context: AdapterContext,
  adapterId: string,
  scope: Scope,
  destination: string
): Promise<InstalledIntegration | null> {
  const marker = await readIfPresent(path.join(destination, SKILL_MARKER_FILE));
  if (marker === null) return null;
  const skillFile = path.join(destination, "SKILL.md");
  return {
    adapterId,
    scope,
    path: skillFile,
    displayPath: displayPath(skillFile, context.repoRoot, context.home),
    payloadVersion: markerVersion(marker) ?? SKILL_BUNDLE_VERSION,
    sharedFile: false
  };
}

async function regionIntegration(
  context: AdapterContext,
  adapterId: string,
  scope: Scope,
  target: string,
  style: MarkerStyle,
  sharedFile: boolean
): Promise<InstalledIntegration | null> {
  const existing = await readIfPresent(target);
  if (existing === null) return null;
  const regions = findManagedRegions(existing.replace(/\r\n/g, "\n"), style);
  if (regions.length === 0) return null;
  return {
    adapterId,
    scope,
    path: target,
    displayPath: displayPath(target, context.repoRoot, context.home),
    payloadVersion: regions[0]?.version ?? "1",
    sharedFile
  };
}

/* ---------- validation ---------- */

/**
 * What one artifact of an integration must look like to be healthy.
 *
 * `validate()` re-derives these from the scope rather than trusting the
 * `InstalledIntegration` it was handed, because an integration with two
 * artifacts — a skill and a pointer — is only as healthy as its worse half, and
 * `installed()` reports one row per scope so `unlink` does not build the same
 * plan twice.
 */
interface Artifact {
  label: string;
  kind: "region" | "skill";
  path: string;
  style: MarkerStyle;
}

const SEVERITY = { healthy: 0, stale: 1, missing: 2, conflicted: 3 } as const;

async function validateArtifact(artifact: Artifact): Promise<ValidationResult> {
  if (artifact.kind === "skill") {
    const marker = await readIfPresent(path.join(artifact.path, SKILL_MARKER_FILE));
    if (marker === null || !(await pathExists(path.join(artifact.path, "SKILL.md")))) {
      return { health: "missing", detail: `The ${artifact.label} is no longer on disk.` };
    }
    if (markerVersion(marker) !== SKILL_BUNDLE_VERSION) {
      return {
        health: "stale",
        detail: `The ${artifact.label} carries bundle ${markerVersion(marker) ?? "unknown"}; this CLI ships ${SKILL_BUNDLE_VERSION}.`,
        remedy: `Run "${BRAND.cliName} link" to update it.`
      };
    }
    return { health: "healthy", detail: `The ${artifact.label} is current.` };
  }

  const existing = await readIfPresent(artifact.path);
  if (existing === null) return { health: "missing", detail: `The ${artifact.label} is no longer on disk.` };
  const regions = findManagedRegions(existing.replace(/\r\n/g, "\n"), artifact.style);
  if (regions.length === 0) {
    return { health: "missing", detail: `The ${artifact.label} no longer contains a ${BRAND.displayName} region.` };
  }
  if (regions.length > 1) {
    return {
      health: "conflicted",
      detail: `The ${artifact.label} contains ${regions.length} ${BRAND.displayName} regions.`,
      remedy: `Delete all but one region, then run "${BRAND.cliName} link".`
    };
  }
  if ((regions[0]?.version ?? "1") !== PAYLOAD_VERSION) {
    return {
      health: "stale",
      detail: `The ${artifact.label} carries payload v${regions[0]?.version ?? "1"}; this CLI writes v${PAYLOAD_VERSION}.`,
      remedy: `Run "${BRAND.cliName} link" to update it.`
    };
  }
  return { health: "healthy", detail: `The ${artifact.label} is current.` };
}

async function validateArtifacts(artifacts: Artifact[]): Promise<ValidationResult> {
  const results = await Promise.all(artifacts.map(validateArtifact));
  let worst = results[0] ?? { health: "missing" as const, detail: "Nothing to validate." };
  for (const result of results) {
    if (SEVERITY[result.health] > SEVERITY[worst.health]) worst = result;
  }
  return worst;
}

/* ---------- Codex CLI ---------- */

/**
 * `$CODEX_HOME` replaces `~/.codex` entirely when it is set, and Codex resolves
 * it before it looks for anything, so an adapter that assumes the default writes
 * a file the user's Codex will never read.
 * https://learn.chatgpt.com/docs/agent-configuration/agents-md
 */
function codexHome(context: AdapterContext): string {
  const configured = context.env.CODEX_HOME?.trim();
  return configured ? path.resolve(configured) : path.join(context.home, ".codex");
}

/**
 * Codex reads only the first non-empty instructions file at the user level, and
 * it checks `AGENTS.override.md` before `AGENTS.md`. When a user has an override
 * file, merging into `AGENTS.md` writes a pointer nothing loads — so the pointer
 * follows Codex's own resolution instead.
 */
async function codexInstructionsFile(context: AdapterContext): Promise<string> {
  const home = codexHome(context);
  const override = path.join(home, "AGENTS.override.md");
  if (await pathExists(override)) return override;
  return path.join(home, "AGENTS.md");
}

/**
 * Codex searches `.agents/skills` from the working directory up to the
 * repository root, then `$HOME/.agents/skills` — the home location keys off the
 * home directory, not off `$CODEX_HOME`.
 * https://learn.chatgpt.com/docs/build-skills
 */
function codexSkillDirectory(context: AdapterContext, scope: Scope): string {
  const root = scope === "project" ? context.repoRoot : context.home;
  return path.join(root, ".agents", "skills", BRAND.skillId);
}

/** `codex --version` prints the release and exits without starting a session. */
const CODEX_CLI: CommandProbe = { command: "codex", flag: "--version" };

export const codexAdapter: AgentAdapter = {
  id: "codex",
  displayName: "Codex CLI",
  documentation: "https://learn.chatgpt.com/docs/agent-configuration/agents-md",
  primitive: "skill",
  platforms: ALL_PLATFORMS,
  probes: [CODEX_CLI],

  async detect(context) {
    const signals: DetectionSignal[] = [];
    let version: string | undefined;

    const executable = await whichExecutable("codex", context);
    if (executable) {
      signals.push({ kind: "executable", detail: "codex on PATH" });
      version = await probeVersion(context, CODEX_CLI, executable, signals);
    }

    const configured = context.env.CODEX_HOME?.trim();
    if (configured) signals.push({ kind: "environment_variable", detail: "CODEX_HOME is set" });
    const home = codexHome(context);
    if (await directoryExists(home)) {
      signals.push({
        kind: "config_directory",
        detail: `Codex home at ${displayPath(home, context.repoRoot, context.home)}`
      });
    }

    const projectSkill = await projectFileSignal(
      path.join(".agents", "skills", BRAND.skillId, "SKILL.md"),
      context
    );
    if (projectSkill) signals.push(projectSkill);

    return verdict(signals, version);
  },

  supportedScopes() {
    return ["project", "global"];
  },

  async createInstallPlan(context, scope) {
    const writes = await planSkillBundle(context, codexSkillDirectory(context, scope));
    const notes = [
      `Invoke it in a Codex session with "$${BRAND.skillId}", or run "${BRAND.cliName} auto" from any shell.`
    ];

    if (scope === "project") {
      // Codex has no project-scoped instructions file of its own: it reads
      // AGENTS.md, and AGENTS.override.md would suppress whatever the user's
      // own AGENTS.md says. So this scope writes the skill and nothing else,
      // and says out loud which adapter owns the other half.
      notes.push(
        `Codex reads AGENTS.md for always-on instructions. That file belongs to the shared AGENTS.md integration, so nothing here touches it — run "${BRAND.cliName} link --agent agents-md" to add the pointer.`
      );
      notes.push(".agents/skills is the portable skill location, so this one install also serves the other agents that read it.");
    } else {
      const instructions = await codexInstructionsFile(context);
      writes.push(await planMergedRegion(context, instructions, pointerBody(true), "html"));
      if (path.basename(instructions) === "AGENTS.override.md") {
        notes.push("Codex reads AGENTS.override.md instead of AGENTS.md when it exists, so the pointer goes there.");
      }
      if (context.env.CODEX_HOME?.trim()) {
        notes.push(`CODEX_HOME is set, so the instructions file is ${displayPath(instructions, context.repoRoot, context.home)}.`);
      }
    }

    return { adapterId: this.id, displayName: this.displayName, scope, writes, notes };
  },

  async installed(context) {
    const found: InstalledIntegration[] = [];
    for (const scope of ["project", "global"] as const) {
      const skill = await skillIntegration(context, this.id, scope, codexSkillDirectory(context, scope));
      if (skill) {
        found.push(skill);
        continue;
      }
      if (scope !== "global") continue;
      const region = await regionIntegration(context, this.id, scope, await codexInstructionsFile(context), "html", true);
      if (region) found.push(region);
    }
    return found;
  },

  async validate(context, integration) {
    const artifacts: Artifact[] = [
      { label: "Codex skill", kind: "skill", path: codexSkillDirectory(context, integration.scope), style: "html" }
    ];
    if (integration.scope === "global") {
      artifacts.push({
        label: "Codex instructions file",
        kind: "region",
        path: await codexInstructionsFile(context),
        style: "html"
      });
    }
    return validateArtifacts(artifacts);
  },

  async createUninstallPlan(context, scope) {
    const writes = await planSkillBundleRemoval(context, codexSkillDirectory(context, scope));
    if (scope === "global") {
      const region = await planMergedRemoval(context, await codexInstructionsFile(context), "html");
      if (region) writes.push(region);
    }
    return { adapterId: this.id, displayName: this.displayName, scope, writes, notes: [] };
  }
};

/* ---------- Kiro ---------- */

function kiroRoot(context: AdapterContext, scope: Scope): string {
  return path.join(scope === "project" ? context.repoRoot : context.home, ".kiro");
}

function kiroSteeringFile(context: AdapterContext, scope: Scope): string {
  return path.join(kiroRoot(context, scope), "steering", `${BRAND.skillId}.md`);
}

function kiroSkillDirectory(context: AdapterContext, scope: Scope): string {
  return path.join(kiroRoot(context, scope), "skills", BRAND.skillId);
}

/**
 * Kiro requires the frontmatter to be the very first content in a steering file
 * — no blank line, no comment ahead of it — which is why the managed marker
 * sits after the closing `---` and is an HTML comment rather than anything that
 * could be mistaken for a YAML key.
 *
 * `inclusion: manual` keeps the file out of every unrelated conversation; the
 * user pulls it in with `#myrqen` when they want it, and the skill covers the
 * case where they simply ask for a security review.
 * https://kiro.dev/docs/steering/
 */
function kiroSteeringContents(): string {
  return ownedFileContents("html", pointerBody(true, BRAND.skillId), "---\ninclusion: manual\n---\n\n");
}

/**
 * Kiro ships under two names and both print a version and exit. The docs use
 * "launch Kiro" alongside `kiro-cli doctor`, so neither is authoritative on its
 * own and both are declared.
 */
const KIRO_CLIS: readonly CommandProbe[] = Object.freeze([
  { command: "kiro", flag: "--version" },
  { command: "kiro-cli", flag: "--version" }
]);

export const kiroAdapter: AgentAdapter = {
  id: "kiro",
  displayName: "Kiro",
  documentation: "https://kiro.dev/docs/steering/",
  primitive: "skill",
  platforms: ALL_PLATFORMS,
  probes: KIRO_CLIS,

  async detect(context) {
    const signals: DetectionSignal[] = [];
    let version: string | undefined;

    // Either name is proof enough on its own; the first one that answers also
    // supplies the version, when this run is allowed to ask for one.
    for (const probe of KIRO_CLIS) {
      const executable = await whichExecutable(probe.command, context);
      if (!executable) continue;
      signals.push({ kind: "executable", detail: `${probe.command} on PATH` });
      version = version ?? (await probeVersion(context, probe, executable, signals));
    }

    // The application bundle name is not stated on an official page, so it only
    // ever adds to a verdict and never carries one on its own.
    const application = await applicationInstalled(["Kiro"], context);
    if (application) signals.push({ kind: "application", detail: displayPath(application, context.repoRoot, context.home) });

    const configDirectory = await configDirectorySignal(".kiro", context, "Kiro configuration");
    if (configDirectory) signals.push(configDirectory);

    const projectSteering = await projectFileSignal(path.join(".kiro", "steering"), context);
    if (projectSteering) signals.push(projectSteering);

    return verdict(signals, version);
  },

  supportedScopes() {
    // Both are documented: `.kiro/steering` and `.kiro/skills` in the workspace,
    // `~/.kiro/steering` and `~/.kiro/skills` for the user.
    return ["project", "global"];
  },

  async createInstallPlan(context, scope) {
    const writes = await planSkillBundle(context, kiroSkillDirectory(context, scope));
    writes.push(await planOwnedFile(context, kiroSteeringFile(context, scope), kiroSteeringContents(), "html"));
    return {
      adapterId: this.id,
      displayName: this.displayName,
      scope,
      writes,
      notes: [
        `Invoke the skill with "/${BRAND.skillId}" in Kiro, or run "${BRAND.cliName} auto" from any shell.`,
        `The steering file uses "inclusion: manual", so it costs nothing until you pull it in with "#${BRAND.skillId}".`
      ]
    };
  },

  async installed(context) {
    const found: InstalledIntegration[] = [];
    for (const scope of ["project", "global"] as const) {
      const skill = await skillIntegration(context, this.id, scope, kiroSkillDirectory(context, scope));
      if (skill) {
        found.push(skill);
        continue;
      }
      const steering = await regionIntegration(context, this.id, scope, kiroSteeringFile(context, scope), "html", false);
      if (steering) found.push(steering);
    }
    return found;
  },

  async validate(context, integration) {
    return validateArtifacts([
      { label: "Kiro skill", kind: "skill", path: kiroSkillDirectory(context, integration.scope), style: "html" },
      { label: "Kiro steering file", kind: "region", path: kiroSteeringFile(context, integration.scope), style: "html" }
    ]);
  },

  async createUninstallPlan(context, scope) {
    const writes = await planSkillBundleRemoval(context, kiroSkillDirectory(context, scope));
    const steering = await planOwnedFileRemoval(context, kiroSteeringFile(context, scope), "html");
    if (steering) writes.push(steering);
    return { adapterId: this.id, displayName: this.displayName, scope, writes, notes: [] };
  }
};

/* ---------- Aider ---------- */

/**
 * Aider reads no rules file automatically. A conventions file is an ordinary
 * Markdown file that only reaches the model because `.aider.conf.yml` lists it
 * under `read:`. Writing the Markdown alone would give an Aider user nothing at
 * all while looking exactly like a successful install, so the two writes are one
 * integration and the config edit is the half that matters.
 * https://aider.chat/docs/usage/conventions.html
 */
const AIDER_CONVENTIONS_FILE = `${BRAND.uppercaseName}.md`;
const AIDER_CONFIG_FILE = ".aider.conf.yml";

function aiderConventionsPath(context: AdapterContext): string {
  return path.join(context.repoRoot, AIDER_CONVENTIONS_FILE);
}

function aiderConfigPath(context: AdapterContext): string {
  return path.join(context.repoRoot, AIDER_CONFIG_FILE);
}

/** `read:`, allowing the quoted spellings YAML also accepts for a plain key. */
const READ_KEY = /^(["']?)read\1[ \t]*:(.*)$/;
const BLOCK_ITEM = /^([ \t]+)-[ \t]*(.*)$/;

function unquote(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length > 1 && (trimmed.startsWith('"') || trimmed.startsWith("'")) && trimmed.endsWith(trimmed[0]!)) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

/** Line indices covered by a Myrqen region, so the user's own keys can be told apart from ours. */
function managedLines(lines: string[], text: string): Set<number> {
  const covered = new Set<number>();
  const offsets: number[] = [];
  let cursor = 0;
  for (const line of lines) {
    offsets.push(cursor);
    cursor += line.length + 1;
  }
  for (const region of findManagedRegions(text, "hash")) {
    for (let index = 0; index < lines.length; index += 1) {
      const start = offsets[index] ?? 0;
      if (start >= region.start && start < region.end) covered.add(index);
    }
  }
  return covered;
}

function topLevelReadKeys(lines: string[], covered: Set<number>): number[] {
  const found: number[] = [];
  for (let index = 0; index < lines.length; index += 1) {
    if (covered.has(index)) continue;
    if (READ_KEY.test(lines[index] ?? "")) found.push(index);
  }
  return found;
}

/** The block-sequence items belonging to a `read:` key, with the line they sit on. */
function blockItems(lines: string[], keyIndex: number): Array<{ index: number; indent: string; value: string }> {
  const items: Array<{ index: number; indent: string; value: string }> = [];
  for (let index = keyIndex + 1; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    if (line.trim() === "" || line.trimStart().startsWith("#")) continue;
    const match = BLOCK_ITEM.exec(line);
    if (!match) break;
    items.push({ index, indent: match[1] ?? "  ", value: unquote(stripComment(match[2] ?? "")) });
  }
  return items;
}

/** Drop a trailing `# comment` from an unquoted scalar; a quoted one is returned whole. */
function stripComment(value: string): string {
  const trimmed = value.trim();
  if (trimmed.startsWith('"') || trimmed.startsWith("'")) return trimmed;
  const comment = /\s#/.exec(trimmed);
  return comment ? trimmed.slice(0, comment.index).trim() : trimmed;
}

type ConfigEdit =
  | { kind: "unchanged" }
  | { kind: "rewrite"; lines: string[] }
  | { kind: "blocked"; reason: string };

/**
 * Add one entry to an existing `read:` key, changing nothing else.
 *
 * `.aider.conf.yml` is a file the user owns, frequently with comments that
 * explain a team's choices. Parsing it into an object and serialising it back
 * would silently delete every one of those comments and reorder the keys, so
 * this edits the specific lines it understands and refuses the rest — a blocked
 * write with an instruction is a far better outcome than a reformatted config.
 */
function addReadEntry(lines: string[], keyIndex: number, entry: string): ConfigEdit {
  const line = lines[keyIndex] ?? "";
  const match = READ_KEY.exec(line);
  if (!match) return { kind: "blocked", reason: "the \"read:\" key could not be read" };
  const value = (match[2] ?? "").trim();

  if (value === "" || value.startsWith("#")) {
    const items = blockItems(lines, keyIndex);
    if (items.some((item) => item.value === entry)) return { kind: "unchanged" };
    if (items.length > 0) {
      const last = items[items.length - 1]!;
      const next = [...lines];
      next.splice(last.index + 1, 0, `${last.indent}- ${entry}`);
      return { kind: "rewrite", lines: next };
    }
    // The key has no value at all. Anything indented under it that is not a
    // sequence item is a mapping, which `read:` cannot hold, so it is refused
    // rather than guessed at.
    const following = lines.slice(keyIndex + 1).find((candidate) => candidate.trim() !== "" && !candidate.trimStart().startsWith("#"));
    if (following !== undefined && /^[ \t]/.test(following)) {
      return { kind: "blocked", reason: "the \"read:\" key holds something this tool will not rewrite" };
    }
    const next = [...lines];
    next.splice(keyIndex + 1, 0, `  - ${entry}`);
    return { kind: "rewrite", lines: next };
  }

  if (value.startsWith("[")) {
    const close = value.lastIndexOf("]");
    if (close === -1) return { kind: "blocked", reason: "the \"read:\" list spans several lines" };
    const inner = value.slice(1, close);
    if (/[[{]/.test(inner)) return { kind: "blocked", reason: "the \"read:\" list contains nested structure" };
    if (inner.split(",").map(unquote).includes(entry)) return { kind: "unchanged" };
    const separator = inner.trim() === "" ? "" : ", ";
    const rebuilt = `${value.slice(0, close)}${separator}${entry}${value.slice(close)}`;
    const next = [...lines];
    next[keyIndex] = `${line.slice(0, line.indexOf(":") + 1)} ${rebuilt}`;
    return { kind: "rewrite", lines: next };
  }

  // A single scalar. Becoming a two-item list is the only way to keep both
  // paths, and any trailing comment stays on the key line where it still reads
  // as the user wrote it.
  const scalar = stripComment(value);
  if (unquote(scalar) === entry) return { kind: "unchanged" };
  const comment = value.slice(scalar.length).trim();
  const keyText = line.slice(0, line.indexOf(":") + 1);
  const next = [...lines];
  next.splice(keyIndex, 1, `${keyText}${comment ? ` ${comment}` : ""}`, `  - ${scalar}`, `  - ${entry}`);
  return { kind: "rewrite", lines: next };
}

function removeReadEntry(lines: string[], keyIndex: number, entry: string): ConfigEdit {
  const line = lines[keyIndex] ?? "";
  const match = READ_KEY.exec(line);
  if (!match) return { kind: "unchanged" };
  const value = (match[2] ?? "").trim();

  if (value === "" || value.startsWith("#")) {
    const item = blockItems(lines, keyIndex).find((candidate) => candidate.value === entry);
    if (!item) return { kind: "unchanged" };
    const next = [...lines];
    next.splice(item.index, 1);
    return { kind: "rewrite", lines: next };
  }

  if (value.startsWith("[")) {
    const close = value.lastIndexOf("]");
    if (close === -1) return { kind: "unchanged" };
    const inner = value.slice(1, close);
    const kept = inner.split(",").filter((element) => element.trim() !== "" && unquote(element) !== entry);
    if (kept.length === inner.split(",").filter((element) => element.trim() !== "").length) return { kind: "unchanged" };
    const rebuilt = `[${kept.join(",").trim() === "" ? "" : kept.map((element) => element.trim()).join(", ")}]${value.slice(close + 1)}`;
    const next = [...lines];
    next[keyIndex] = `${line.slice(0, line.indexOf(":") + 1)} ${rebuilt}`;
    return { kind: "rewrite", lines: next };
  }

  if (unquote(stripComment(value)) !== entry) return { kind: "unchanged" };
  const next = [...lines];
  next.splice(keyIndex, 1);
  return { kind: "rewrite", lines: next };
}

/** The managed region Myrqen writes when the config has no `read:` key of its own. */
function aiderRegionBody(): string {
  return [
    `# Aider only loads a conventions file that is listed here.`,
    `read:`,
    `  - ${AIDER_CONVENTIONS_FILE}`
  ].join("\n");
}

async function planAiderConfig(context: AdapterContext, removing: boolean): Promise<PlannedWrite> {
  const target = aiderConfigPath(context);
  const existing = await readIfPresent(target);

  if (existing === null || existing.trim() === "") {
    if (removing) return planned(context, target, "unchanged");
    const merged = mergeManagedRegion(existing, aiderRegionBody(), "hash");
    return planned(context, target, "create", { contents: merged.contents });
  }

  const crlf = /\r\n/.test(existing);
  const normalized = existing.replace(/\r\n/g, "\n");
  const lines = normalized.split("\n");
  const covered = managedLines(lines, normalized);
  const userKeys = topLevelReadKeys(lines, covered);
  const hasRegion = findManagedRegions(normalized, "hash").length > 0;

  if (userKeys.length > 1) {
    return planned(context, target, "blocked", {
      preservesExistingContent: true,
      reason: `this file has ${userKeys.length} top-level "read:" keys; fix that first`
    });
  }

  // Both a Myrqen region and the user's own `read:` key means YAML with two
  // copies of one key. Myrqen will not decide which of them wins.
  if (hasRegion && userKeys.length === 1) {
    return planned(context, target, "blocked", {
      preservesExistingContent: true,
      reason: `a "read:" key was added outside the ${BRAND.displayName} region; merge the two by hand, then run "${BRAND.cliName} link" again`
    });
  }

  // No `read:` of the user's own, so Myrqen brings its own key inside a marked
  // region and the rest of the file is untouched.
  if (userKeys.length === 0) {
    if (!removing) return planMergedRegion(context, target, aiderRegionBody(), "hash");
    const removal = removeManagedRegion(existing, "hash");
    if (!removal.removed) return planned(context, target, "unchanged", { preservesExistingContent: true });
    if (removal.empty) return planned(context, target, "remove");
    return planned(context, target, "remove", { contents: removal.contents, preservesExistingContent: true });
  }

  const keyIndex = userKeys[0]!;
  const edit = removing
    ? removeReadEntry(lines, keyIndex, AIDER_CONVENTIONS_FILE)
    : addReadEntry(lines, keyIndex, AIDER_CONVENTIONS_FILE);

  if (edit.kind === "unchanged") {
    return planned(context, target, "unchanged", { preservesExistingContent: true });
  }
  if (edit.kind === "blocked") {
    return planned(context, target, "blocked", {
      preservesExistingContent: true,
      reason: `${edit.reason}; add "- ${AIDER_CONVENTIONS_FILE}" under "read:" by hand`
    });
  }

  const rebuilt = edit.lines.join("\n");
  const contents = crlf ? rebuilt.replace(/\n/g, "\r\n") : rebuilt;
  return planned(context, target, removing ? "remove" : "merge", { contents, preservesExistingContent: true });
}

/** `aider --version` prints the release and exits without opening a repository. */
const AIDER_CLI: CommandProbe = { command: "aider", flag: "--version" };

export const aiderAdapter: AgentAdapter = {
  id: "aider",
  displayName: "Aider",
  documentation: "https://aider.chat/docs/usage/conventions.html",
  primitive: "rules_file",
  platforms: ALL_PLATFORMS,
  probes: [AIDER_CLI],

  async detect(context) {
    const signals: DetectionSignal[] = [];
    let version: string | undefined;

    const executable = await whichExecutable("aider", context);
    if (executable) {
      signals.push({ kind: "executable", detail: "aider on PATH" });
      version = await probeVersion(context, AIDER_CLI, executable, signals);
    }

    // Existence only. The config may name a model provider, and nothing here
    // opens it.
    const userConfig = path.join(context.home, AIDER_CONFIG_FILE);
    if (await pathExists(userConfig)) {
      signals.push({ kind: "config_file", detail: displayPath(userConfig, context.repoRoot, context.home) });
    }
    const projectConfig = await projectFileSignal(AIDER_CONFIG_FILE, context);
    if (projectConfig) signals.push(projectConfig);

    return verdict(signals, version);
  },

  supportedScopes() {
    // Project only. Aider documents `.aider.conf.yml` in the home directory, but
    // documents no home location for the conventions file it would have to point
    // at, and inventing one is exactly the reverse engineering this layer avoids.
    return ["project"];
  },

  async createInstallPlan(context, scope) {
    const conventions = await planOwnedFile(
      context,
      aiderConventionsPath(context),
      ownedFileContents("html", pointerBody(false)),
      "html"
    );
    const config = await planAiderConfig(context, false);
    const notes = [
      `Aider loads a conventions file only when ${AIDER_CONFIG_FILE} lists it, which is why both files are in this plan.`,
      `Start aider as usual; ${AIDER_CONVENTIONS_FILE} is loaded read-only. Run "${BRAND.cliName} auto" for the assessment itself.`
    ];
    if (config.action === "blocked") {
      notes.push(
        `Until that is done, ${AIDER_CONVENTIONS_FILE} sits in the project but aider will not read it. Adding "- ${AIDER_CONVENTIONS_FILE}" under "read:" is the whole fix.`
      );
    }
    return { adapterId: this.id, displayName: this.displayName, scope, writes: [conventions, config], notes };
  },

  async installed(context) {
    const conventions = await regionIntegration(context, this.id, "project", aiderConventionsPath(context), "html", false);
    return conventions ? [conventions] : [];
  },

  async validate(context) {
    const conventions = await validateArtifact({
      label: `${BRAND.displayName} conventions file`,
      kind: "region",
      path: aiderConventionsPath(context),
      style: "html"
    });
    if (conventions.health !== "healthy") return conventions;

    // A healthy conventions file that nothing loads is the failure mode unique
    // to aider, so it is checked separately and reported as a real problem.
    const config = await readIfPresent(aiderConfigPath(context));
    if (config === null || !config.includes(AIDER_CONVENTIONS_FILE)) {
      return {
        health: "conflicted",
        detail: `${AIDER_CONVENTIONS_FILE} exists but ${AIDER_CONFIG_FILE} does not list it, so aider never loads it.`,
        remedy: `Run "${BRAND.cliName} link --agent aider", or add "- ${AIDER_CONVENTIONS_FILE}" under "read:" yourself.`
      };
    }
    return conventions;
  },

  async createUninstallPlan(context, scope) {
    const writes: PlannedWrite[] = [];
    const conventions = await planOwnedFileRemoval(context, aiderConventionsPath(context), "html");
    if (conventions) writes.push(conventions);
    const config = await planAiderConfig(context, true);
    if (config.action !== "unchanged") writes.push(config);
    return { adapterId: this.id, displayName: this.displayName, scope, writes, notes: [] };
  }
};

/* ---------- OpenCode ---------- */

/**
 * OpenCode reads `.opencode/skills/<name>/SKILL.md` in the project, walking up
 * to the git worktree, and `~/.config/opencode/skills/<name>/SKILL.md` for the
 * user. The home path is spelled out rather than resolved through
 * XDG_CONFIG_HOME because `~/.config/opencode` is what the documentation states
 * and what the CLI's own installer already targets.
 * https://opencode.ai/docs/skills/
 */
function opencodeSkillDirectory(context: AdapterContext, scope: Scope): string {
  return scope === "project"
    ? path.join(context.repoRoot, ".opencode", "skills", BRAND.skillId)
    : path.join(context.home, ".config", "opencode", "skills", BRAND.skillId);
}

/** `opencode --version` prints the release and exits. */
const OPENCODE_CLI: CommandProbe = { command: "opencode", flag: "--version" };

export const opencodeAdapter: AgentAdapter = {
  id: "opencode",
  displayName: "OpenCode",
  documentation: "https://opencode.ai/docs/skills/",
  primitive: "skill",
  platforms: ALL_PLATFORMS,
  probes: [OPENCODE_CLI],

  async detect(context) {
    const signals: DetectionSignal[] = [];
    let version: string | undefined;

    const executable = await whichExecutable("opencode", context);
    if (executable) {
      signals.push({ kind: "executable", detail: "opencode on PATH" });
      version = await probeVersion(context, OPENCODE_CLI, executable, signals);
    }

    const configDirectory = await configDirectorySignal(path.join(".config", "opencode"), context, "OpenCode configuration");
    if (configDirectory) signals.push(configDirectory);

    const projectDirectory = await projectFileSignal(".opencode", context);
    if (projectDirectory) signals.push(projectDirectory);

    return verdict(signals, version);
  },

  supportedScopes() {
    return ["project", "global"];
  },

  async createInstallPlan(context, scope) {
    return {
      adapterId: this.id,
      displayName: this.displayName,
      scope,
      writes: await planSkillBundle(context, opencodeSkillDirectory(context, scope)),
      notes: [
        "OpenCode loads this through its own skill tool and chooses it by description, so there is no command to remember.",
        `Run "${BRAND.cliName} auto" from any shell to start the assessment yourself.`
      ]
    };
  },

  async installed(context) {
    const found: InstalledIntegration[] = [];
    for (const scope of ["project", "global"] as const) {
      const skill = await skillIntegration(context, this.id, scope, opencodeSkillDirectory(context, scope));
      if (skill) found.push(skill);
    }
    return found;
  },

  async validate(context, integration) {
    return validateArtifact({
      label: "OpenCode skill",
      kind: "skill",
      path: opencodeSkillDirectory(context, integration.scope),
      style: "html"
    });
  },

  async createUninstallPlan(context, scope) {
    return {
      adapterId: this.id,
      displayName: this.displayName,
      scope,
      writes: await planSkillBundleRemoval(context, opencodeSkillDirectory(context, scope)),
      notes: []
    };
  }
};
