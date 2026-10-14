import path from "node:path";
import { BRAND } from "@myrqen/brand";
import {
  PAYLOAD_VERSION,
  directoryExists,
  displayPath,
  endMarker,
  findManagedRegions,
  mergeManagedRegion,
  ownedFileHeader,
  readIfPresent,
  removeManagedRegion,
  type ManagedRegion,
  type MarkerStyle
} from "../managed.js";
import {
  configDirectorySignal,
  editorExtension,
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
  InstallPlan,
  InstalledIntegration,
  PlannedWrite,
  Scope,
  ValidationResult
} from "../types.js";

/**
 * GitHub Copilot and Gemini CLI.
 *
 * These two agents sit at opposite ends of the "how much of this file is mine"
 * question, which is why they share a file: the contrast is the point.
 *
 * Copilot reads a *directory* of instruction files, so Myrqen writes one file it
 * owns outright and never touches `.github/copilot-instructions.md`, which is
 * where a team keeps the instructions they argued about.
 *
 * Gemini reads one file per scope — `GEMINI.md` — and concatenates every one it
 * finds into every prompt. There is no dedicated-file escape hatch, so Myrqen
 * owns a marked region inside a file that belongs to the user, and the payload
 * stays a pointer for exactly that reason: whatever goes in there is paid for on
 * every prompt in the project, including the ones about CSS.
 */

/** Markdown is the format on both sides, and an HTML comment is the only marker that survives it. */
const MARKER: MarkerStyle = "html";

const DESKTOP_PLATFORMS = ["darwin", "linux", "win32"] as const satisfies readonly NodeJS.Platform[];

/**
 * What goes inside the managed region.
 *
 * The pointer, never the method. Both files here are read at the top of every
 * conversation, so the whole job of this text is to make the agent reach for the
 * real method at the right moment and cost nothing the rest of the time.
 */
function managedBody(): string {
  return `${pointerPayload({ skillAvailable: false })}\n\n${provenanceLine()}`;
}

function shown(target: string, context: AdapterContext): string {
  return displayPath(target, context.repoRoot, context.home);
}

/**
 * Plan a file Myrqen owns end to end.
 *
 * A file with our name that we did not write is somebody else's work: it is
 * blocked rather than overwritten, because a user who hand-wrote
 * `myrqen.instructions.md` before running `myrqen link` should get it back
 * unharmed, and a diff they never see is not consent.
 *
 * The comparison normalises line endings so a repository checked out with CRLF
 * reports `unchanged` instead of rewriting the file on every run.
 */
async function planOwnedFile(target: string, contents: string, context: AdapterContext): Promise<PlannedWrite> {
  const displayed = shown(target, context);
  const existing = await readIfPresent(target);

  if (existing === null) {
    return { path: target, displayPath: displayed, action: "create", contents, preservesExistingContent: false };
  }
  if (findManagedRegions(existing, MARKER).length === 0) {
    return {
      path: target,
      displayPath: displayed,
      action: "blocked",
      preservesExistingContent: true,
      reason: `this file already exists and ${BRAND.displayName} did not write it — rename it, then run "${BRAND.cliName} link" again`
    };
  }
  if (existing.replace(/\r\n/g, "\n") === contents) {
    return { path: target, displayPath: displayed, action: "unchanged", preservesExistingContent: false };
  }
  return { path: target, displayPath: displayed, action: "update", contents, preservesExistingContent: false };
}

async function planOwnedFileRemoval(target: string, context: AdapterContext): Promise<PlannedWrite> {
  const displayed = shown(target, context);
  const existing = await readIfPresent(target);

  if (existing === null) {
    return { path: target, displayPath: displayed, action: "unchanged", preservesExistingContent: false };
  }
  if (findManagedRegions(existing, MARKER).length === 0) {
    return {
      path: target,
      displayPath: displayed,
      action: "blocked",
      preservesExistingContent: true,
      reason: `this file carries no ${BRAND.displayName} marker, so it is not ours to delete`
    };
  }
  // No `contents`: the applier deletes the file, and then any directory Myrqen
  // created for it that is now empty.
  return { path: target, displayPath: displayed, action: "remove", preservesExistingContent: false };
}

/** Plan a marked region inside a file the user owns. */
async function planSharedFile(target: string, context: AdapterContext): Promise<PlannedWrite> {
  const displayed = shown(target, context);
  const existing = await readIfPresent(target);
  const merged = mergeManagedRegion(existing, managedBody(), MARKER);

  if (merged.action === "conflicted") {
    return {
      path: target,
      displayPath: displayed,
      action: "blocked",
      preservesExistingContent: true,
      reason: `this file holds more than one ${BRAND.displayName} section — delete all but one, then run "${BRAND.cliName} link" again`
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

async function planSharedFileRemoval(target: string, context: AdapterContext): Promise<PlannedWrite> {
  const displayed = shown(target, context);
  const existing = await readIfPresent(target);

  if (existing === null) {
    return { path: target, displayPath: displayed, action: "unchanged", preservesExistingContent: false };
  }
  const removal = removeManagedRegion(existing, MARKER);
  if (!removal.removed) {
    return { path: target, displayPath: displayed, action: "unchanged", preservesExistingContent: true };
  }
  if (removal.empty) {
    // The file held nothing but our section, which means Myrqen created it.
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

/** True when the text holds anything outside the managed regions. */
function holdsForeignContent(text: string, regions: ManagedRegion[]): boolean {
  let remaining = text;
  for (const region of [...regions].reverse()) {
    remaining = remaining.slice(0, region.start) + remaining.slice(region.end);
  }
  return remaining.trim().length > 0;
}

/**
 * Reconstruct one installed integration by reading the file, never a database.
 *
 * A record of what Myrqen installed that lives anywhere other than the installed
 * file itself goes stale the first time somebody edits their dotfiles by hand,
 * and then `status` lies.
 */
async function readInstalled(
  adapterId: string,
  scope: Scope,
  target: string,
  context: AdapterContext,
  sharedFile: boolean | "detect"
): Promise<InstalledIntegration | null> {
  const existing = await readIfPresent(target).catch(() => null);
  if (existing === null) return null;
  const regions = findManagedRegions(existing, MARKER);
  const first = regions[0];
  if (!first) return null;

  return {
    adapterId,
    scope,
    path: target,
    displayPath: shown(target, context),
    payloadVersion: first.version ?? "1",
    sharedFile: sharedFile === "detect" ? holdsForeignContent(existing, regions) : sharedFile
  };
}

async function validateManagedFile(integration: InstalledIntegration): Promise<ValidationResult> {
  const existing = await readIfPresent(integration.path).catch(() => null);
  if (existing === null) {
    return {
      health: "missing",
      detail: `${integration.displayPath} is no longer on disk.`,
      remedy: `Run "${BRAND.cliName} link" to write it again.`
    };
  }

  const regions = findManagedRegions(existing, MARKER);
  const first = regions[0];
  if (!first) {
    return {
      health: "missing",
      detail: `${integration.displayPath} no longer contains a ${BRAND.displayName} section.`,
      remedy: `Run "${BRAND.cliName} link" to write it again.`
    };
  }
  if (regions.length > 1) {
    return {
      health: "conflicted",
      detail: `${integration.displayPath} contains ${regions.length} ${BRAND.displayName} sections, which is one more than can be updated safely.`,
      remedy: `Delete all but one, then run "${BRAND.cliName} link".`
    };
  }
  if ((first.version ?? "1") !== PAYLOAD_VERSION) {
    return {
      health: "stale",
      detail: `${integration.displayPath} carries payload v${first.version ?? "1"}; this release writes v${PAYLOAD_VERSION}.`,
      remedy: `Run "${BRAND.cliName} link" to refresh it.`
    };
  }
  return { health: "healthy", detail: `${integration.displayPath} carries the current payload.` };
}

/* ------------------------------------------------------------------ Copilot */

const COPILOT_ID = "github-copilot";
const COPILOT_FILE = "myrqen.instructions.md";

/**
 * The Copilot extension ids, compared case-insensitively by `editorExtension`.
 * Chat used to be a separate extension and still is on older installs, so both
 * count as proof.
 */
const COPILOT_EXTENSIONS = ["github.copilot", "github.copilot-chat"] as const;

/** Every VS Code-compatible editor Myrqen supports. A Cursor user with Copilot installed is a Copilot user. */
const COPILOT_EDITORS = ["code", "code-insiders", "cursor", "windsurf"] as const;

/**
 * Copilot CLI's configuration directory.
 *
 * `COPILOT_HOME` replaces the whole path rather than being appended to, per the
 * CLI config-dir reference, and it is honoured because a user who moved their
 * Copilot configuration meant it. A relative value is ignored: resolving it
 * against the process's working directory would put personal instructions in
 * whatever repository happened to be open.
 */
function copilotHome(context: AdapterContext): string {
  const override = context.env.COPILOT_HOME;
  if (override && path.isAbsolute(override)) return override;
  return path.join(context.home, ".copilot");
}

function copilotTarget(context: AdapterContext, scope: Scope): string {
  return scope === "project"
    ? path.join(context.repoRoot, ".github", "instructions", COPILOT_FILE)
    : path.join(copilotHome(context), "instructions", COPILOT_FILE);
}

/**
 * The instructions file, frontmatter and all.
 *
 * `applyTo` is the field that decides whether Copilot loads the file at all:
 * omit it and the file is never auto-applied, which produces a file nobody ever
 * reads. `'**'` is quoted because a bare `*` opens a YAML alias node and the
 * frontmatter would fail to parse.
 *
 * The frontmatter has to come first, so the managed marker opens the body
 * underneath it rather than above — an HTML comment before `---` would stop the
 * frontmatter being frontmatter.
 */
function copilotContents(): string {
  const frontmatter = [
    "---",
    `name: ${BRAND.displayName} security assessment`,
    `description: When and how to run a ${BRAND.displayName} security assessment of this project.`,
    "applyTo: '**'",
    "---"
  ].join("\n");

  const region = [ownedFileHeader(MARKER), "", managedBody(), endMarker(MARKER)].join("\n");
  return `${frontmatter}\n\n${region}\n`;
}

async function copilotNotes(context: AdapterContext, scope: Scope): Promise<string[]> {
  const notes: string[] = [];

  if (scope === "project") {
    notes.push(
      `Copilot reads every *.instructions.md under .github/instructions, in VS Code, on github.com, and in the CLI, so ${BRAND.displayName} gets a file of its own.`
    );
    // Stated only when the file is actually there: telling someone their file
    // was left alone when they do not have one is noise.
    if (await readIfPresent(path.join(context.repoRoot, ".github", "copilot-instructions.md")).then((value) => value !== null)) {
      notes.push("Your .github/copilot-instructions.md is left exactly as it is.");
    }
  } else {
    notes.push("Personal instructions apply in every repository you open with Copilot.");
    if (context.env.COPILOT_HOME) {
      notes.push("COPILOT_HOME is set, so this went to your configured Copilot directory rather than ~/.copilot.");
    }
  }

  notes.push(`Ask Copilot for a security review, or run "${BRAND.cliName} auto" from any shell.`);
  return notes;
}

/**
 * The Copilot CLI is never executed. Not with `--version`, not with anything.
 *
 * This is the program that made the whole probe policy necessary. On its first
 * run it bootstraps: a reviewer measured one `myrqen status --agents` writing
 * 247 files and 171 MB into the home directory and taking four seconds, purely
 * because detection asked it for a version string. The version was then thrown
 * away, because the timeout killed the child before it answered.
 *
 * The `copilot` binary sitting on PATH already proves Copilot is installed, and
 * that costs a `stat`. There is nothing left for an execution to buy, so this
 * probe carries a reason instead of a flag and `probeRefusal` honours it ahead
 * of every other consideration — a terminal, `--yes`, and a future flag all
 * included.
 */
const COPILOT_CLI: CommandProbe = {
  command: "copilot",
  flag: "--version",
  never:
    `the GitHub Copilot CLI bootstraps itself on first run, writing hundreds of files into the home directory, so ${BRAND.displayName} never launches it`
};

export const copilotAdapter: AgentAdapter = {
  id: COPILOT_ID,
  displayName: "GitHub Copilot",
  // Documents the .instructions.md format, the applyTo field, and both the
  // workspace and personal locations. The CLI's own reference agrees:
  // https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-custom-instructions
  documentation: "https://code.visualstudio.com/docs/copilot/customization/custom-instructions",
  primitive: "instructions_file",
  platforms: DESKTOP_PLATFORMS,
  probes: [COPILOT_CLI],

  async detect(context: AdapterContext): Promise<DetectionResult> {
    const signals: DetectionSignal[] = [];

    // One extension signal is enough. Reporting Copilot four times because four
    // editors have it makes the detection list unreadable without making it
    // more certain.
    findExtension: for (const editor of COPILOT_EDITORS) {
      for (const extension of COPILOT_EXTENSIONS) {
        const found = await editorExtension(editor, extension, context);
        if (found) {
          signals.push(found);
          break findExtension;
        }
      }
    }

    // The path on PATH is the evidence. `probeVersion` will decline — see
    // COPILOT_CLI — so this run leaves the version column empty rather than
    // launching a CLI that unpacks itself into the user's home directory.
    const executable = await whichExecutable("copilot", context);
    if (executable) {
      signals.push({ kind: "executable", detail: `copilot at ${shown(executable, context)}` });
    }
    const version = executable ? await probeVersion(context, COPILOT_CLI, executable, signals) : undefined;

    // Checked directly rather than through configDirectorySignal because
    // COPILOT_HOME can move it out of the user's home entirely.
    const configDirectory = copilotHome(context);
    if (await directoryExists(configDirectory)) {
      signals.push({ kind: "config_directory", detail: `Copilot CLI configuration at ${shown(configDirectory, context)}` });
    }
    if (context.env.COPILOT_HOME) {
      signals.push({ kind: "environment_variable", detail: "COPILOT_HOME is set" });
    }

    const repositoryInstructions = await projectFileSignal(path.join(".github", "copilot-instructions.md"), context);
    if (repositoryInstructions) signals.push(repositoryInstructions);

    return verdict(signals, version);
  },

  // Both are documented: `.github/instructions` for a repository, and the
  // `instructions` directory under the Copilot config dir for one person.
  supportedScopes(): Scope[] {
    return ["project", "global"];
  },

  async createInstallPlan(context: AdapterContext, scope: Scope): Promise<InstallPlan> {
    return {
      adapterId: COPILOT_ID,
      displayName: copilotAdapter.displayName,
      scope,
      writes: [await planOwnedFile(copilotTarget(context, scope), copilotContents(), context)],
      notes: await copilotNotes(context, scope)
    };
  },

  async installed(context: AdapterContext): Promise<InstalledIntegration[]> {
    const found: InstalledIntegration[] = [];
    for (const scope of ["project", "global"] as const) {
      // `sharedFile: false` and not detected: the frontmatter outside the region
      // is Myrqen's own, so there is nothing here belonging to the user.
      const entry = await readInstalled(COPILOT_ID, scope, copilotTarget(context, scope), context, false);
      if (entry) found.push(entry);
    }
    return found;
  },

  async validate(_context: AdapterContext, integration: InstalledIntegration): Promise<ValidationResult> {
    return validateManagedFile(integration);
  },

  async createUninstallPlan(context: AdapterContext, scope: Scope): Promise<InstallPlan> {
    return {
      adapterId: COPILOT_ID,
      displayName: copilotAdapter.displayName,
      scope,
      writes: [await planOwnedFileRemoval(copilotTarget(context, scope), context)],
      notes: ["Nothing else under .github is touched."]
    };
  }
};

/* ------------------------------------------------------------------- Gemini */

const GEMINI_ID = "gemini-cli";
const GEMINI_DEFAULT_FILE = "GEMINI.md";

/**
 * A settings file larger than this is not a settings file, and parsing it would
 * be a denial-of-service Myrqen inflicted on itself during `link`.
 */
const SETTINGS_SIZE_LIMIT = 256 * 1024;

/**
 * Read `context.fileName` out of a Gemini settings file, and nothing else.
 *
 * The file is a general configuration document that can hold an API key, so the
 * parsed value is used for one documented key and dropped. Nothing from it
 * reaches a detection signal, a plan note, or a log line.
 *
 * The name is validated to a bare Markdown basename because a settings file
 * inside a repository is untrusted input: `../../.ssh/authorized_keys` is a
 * legal JSON string, and without this check it would become a write target.
 */
async function configuredContextFileNames(settingsPath: string): Promise<string[]> {
  const raw = await readIfPresent(settingsPath).catch(() => null);
  if (raw === null || raw.length > SETTINGS_SIZE_LIMIT) return [];

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    // A settings file the user is halfway through editing is not an error
    // Myrqen has any business reporting.
    return [];
  }

  const section = (parsed as { context?: { fileName?: unknown } } | null)?.context;
  const configured = section?.fileName;
  const candidates = typeof configured === "string" ? [configured] : Array.isArray(configured) ? configured : [];
  return candidates.filter((name): name is string => typeof name === "string" && isSafeContextFileName(name));
}

function isSafeContextFileName(name: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9._-]*\.md$/.test(name) && path.basename(name) === name;
}

/**
 * Which file Gemini actually reads in this scope.
 *
 * `context.fileName` in settings.json renames the context file, and a project
 * that renamed it would otherwise get a GEMINI.md that Gemini never opens. The
 * project setting is consulted first because it is the closer one; when several
 * names are listed, GEMINI.md wins if it is among them, since that is the name
 * the rest of the ecosystem recognises.
 */
async function geminiContextFileName(context: AdapterContext, scope: Scope): Promise<string> {
  const settingsFiles =
    scope === "project"
      ? [path.join(context.repoRoot, ".gemini", "settings.json"), path.join(context.home, ".gemini", "settings.json")]
      : [path.join(context.home, ".gemini", "settings.json")];

  for (const file of settingsFiles) {
    const names = await configuredContextFileNames(file);
    const preferred = names.find((name) => name === GEMINI_DEFAULT_FILE) ?? names[0];
    if (preferred) return preferred;
  }
  return GEMINI_DEFAULT_FILE;
}

function geminiTarget(context: AdapterContext, scope: Scope, fileName: string): string {
  return scope === "project" ? path.join(context.repoRoot, fileName) : path.join(context.home, ".gemini", fileName);
}

/** `gemini --version` prints the release and exits without starting a session. */
const GEMINI_CLI: CommandProbe = { command: "gemini", flag: "--version" };

export const geminiAdapter: AgentAdapter = {
  id: GEMINI_ID,
  displayName: "Gemini CLI",
  documentation: "https://geminicli.com/docs/cli/gemini-md/",
  primitive: "managed_section",
  platforms: DESKTOP_PLATFORMS,
  probes: [GEMINI_CLI],

  async detect(context: AdapterContext): Promise<DetectionResult> {
    const signals: DetectionSignal[] = [];

    let version: string | undefined;
    const executable = await whichExecutable("gemini", context);
    if (executable) {
      signals.push({ kind: "executable", detail: `gemini at ${shown(executable, context)}` });
      version = await probeVersion(context, GEMINI_CLI, executable, signals);
    }

    // The configuration directory is reported once. `~/.gemini/settings.json`
    // would be a second signal for the same fact, and two restatements of one
    // fact must not add up to the confidence of two independent ones.
    const configDirectory = await configDirectorySignal(".gemini", context, "Gemini CLI configuration");
    if (configDirectory) signals.push(configDirectory);

    const projectContext = await projectFileSignal(GEMINI_DEFAULT_FILE, context);
    if (projectContext) signals.push(projectContext);

    return verdict(signals, version);
  },

  // Both documented: GEMINI.md found by walking up from the workspace, and
  // ~/.gemini/GEMINI.md for the user.
  supportedScopes(): Scope[] {
    return ["project", "global"];
  },

  async createInstallPlan(context: AdapterContext, scope: Scope): Promise<InstallPlan> {
    const fileName = await geminiContextFileName(context, scope);
    const target = geminiTarget(context, scope, fileName);
    const notes = [
      `Every context file Gemini finds is sent with every prompt, so ${BRAND.displayName} keeps its section to a short pointer and loads the method only when you ask for an assessment.`,
      `Anything already in the file is preserved; ${BRAND.displayName} only owns the marked section.`
    ];
    if (fileName !== GEMINI_DEFAULT_FILE) {
      notes.push(`Your Gemini settings name ${fileName} as the context file, so ${BRAND.displayName} wrote there instead of ${GEMINI_DEFAULT_FILE}.`);
    }
    notes.push(`Run "${BRAND.cliName} auto" to start an assessment.`);

    return {
      adapterId: GEMINI_ID,
      displayName: geminiAdapter.displayName,
      scope,
      writes: [await planSharedFile(target, context)],
      notes
    };
  },

  async installed(context: AdapterContext): Promise<InstalledIntegration[]> {
    const found: InstalledIntegration[] = [];
    for (const scope of ["project", "global"] as const) {
      // The default name is checked as well as the configured one, so an
      // integration installed before the setting changed is still reported
      // rather than silently orphaned.
      const names = new Set([await geminiContextFileName(context, scope), GEMINI_DEFAULT_FILE]);
      for (const name of names) {
        const entry = await readInstalled(GEMINI_ID, scope, geminiTarget(context, scope, name), context, "detect");
        if (entry) found.push(entry);
      }
    }
    return found;
  },

  async validate(_context: AdapterContext, integration: InstalledIntegration): Promise<ValidationResult> {
    return validateManagedFile(integration);
  },

  async createUninstallPlan(context: AdapterContext, scope: Scope): Promise<InstallPlan> {
    const names = new Set([await geminiContextFileName(context, scope), GEMINI_DEFAULT_FILE]);
    const writes: PlannedWrite[] = [];
    for (const name of names) {
      writes.push(await planSharedFileRemoval(geminiTarget(context, scope, name), context));
    }
    return {
      adapterId: GEMINI_ID,
      displayName: geminiAdapter.displayName,
      scope,
      writes,
      notes: ["Only the marked section is removed; the rest of the file is left untouched."]
    };
  }
};
