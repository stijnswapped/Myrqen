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
  removeManagedRegion
} from "../managed.js";
import {
  applicationInstalled,
  configDirectorySignal,
  projectFileSignal,
  verdict,
  whichExecutable
} from "../detect.js";
import { probeVersion } from "../probe.js";
import { frontmatterPayload, pointerPayload, provenanceLine, type PayloadContext } from "../payload.js";
import type {
  AdapterContext,
  AgentAdapter,
  CommandProbe,
  DetectionResult,
  DetectionSignal,
  InstalledIntegration,
  PlannedWrite,
  Scope,
  ValidationResult
} from "../types.js";

/**
 * Cursor and Windsurf.
 *
 * Two editors that arrived at the same shape from different directions: a
 * directory of rule files, each carrying frontmatter that decides when the rule
 * enters the model's context. That shape suits Myrqen exactly, because the one
 * thing this integration must never do is put a security methodology in front
 * of the model during a CSS edit. Both rules written here load on demand, and
 * both hold the short pointer rather than the method itself.
 *
 * Neither adapter writes `AGENTS.md`, even though Cursor reads it. Two adapters
 * merging into one file would each see the other's managed region as foreign
 * content, and the second run would fight the first. The AGENTS.md adapter owns
 * that file alone; these two only mention it.
 */

const CURSOR = "Cursor";
const WINDSURF = "Windsurf";

/** Both editors ship for every desktop platform Myrqen supports. */
const PLATFORMS: readonly NodeJS.Platform[] = ["darwin", "linux", "win32"];

/**
 * The one line both formats show the model when deciding whether to load the
 * rule. It is a plain YAML scalar in each of them, so it carries no `: ` and no
 * ` #`: the first would end the value early and the second would start a
 * comment, and in both cases the rule would load with a truncated description
 * or fail to parse at all.
 */
const RULE_DESCRIPTION = `${BRAND.displayName} security assessment. Load this when the user asks whether this project is secure, asks for a security review or a pentest, or wants a vulnerability check before shipping.`;

/**
 * Cursor's three documented `.mdc` fields are what decide when a rule is in
 * context. `alwaysApply: true` loads it on every turn, `globs` attaches it to
 * matching files, and a description on its own leaves the agent to ask for it.
 * Myrqen wants the third.
 *
 * `globs` is deliberately absent. No file extension means "the user is asking
 * about security", so any pattern here would attach an assessment methodology
 * to routine edits — the exact cost this adapter exists to avoid.
 */
const CURSOR_FRONTMATTER: Record<string, string> = {
  description: RULE_DESCRIPTION,
  alwaysApply: "false"
};

/**
 * Windsurf's equivalent switch is `trigger`. `always_on` would put the rule in
 * every Cascade turn, `glob` needs patterns Myrqen has no honest value for, and
 * `manual` hides the rule behind an @-mention the user would have to remember.
 * `model_decision` puts only the description in the system prompt and pulls the
 * body in when it matches, which is the behaviour this payload was written for.
 */
const WINDSURF_FRONTMATTER: Record<string, string> = {
  trigger: "model_decision",
  description: RULE_DESCRIPTION
};

/**
 * Cursor ignores `.md` files inside `.cursor/rules`. The `.mdc` extension is
 * what makes the file readable at all, so it is not a stylistic choice.
 */
function cursorRulePath(context: AdapterContext): string {
  return path.join(context.repoRoot, ".cursor", "rules", `${BRAND.skillId}.mdc`);
}

/**
 * Recent Devin Desktop builds prefer `.devin/rules/` and fall back to
 * `.windsurf/rules/`. Myrqen writes only the fallback: it is read by every
 * released version, old and new, and writing both directories would put the
 * same pointer in front of the model twice on any build that reads them both.
 */
function windsurfProjectRulePath(context: AdapterContext): string {
  return path.join(context.repoRoot, ".windsurf", "rules", `${BRAND.skillId}.md`);
}

/** The one documented user-scoped rules file. It is shared, so it is merged. */
function windsurfGlobalRulesPath(context: AdapterContext): string {
  return path.join(context.home, ".codeium", "windsurf", "memories", "global_rules.md");
}

/**
 * Whether a Myrqen skill bundle sits in a directory Cursor reads.
 *
 * Cursor loads skills from its own directory and, for compatibility, from the
 * portable and Claude Code locations. Which of them exists decides what the
 * pointer tells the agent to run, so the rule never advertises a slash command
 * that would do nothing on this machine.
 */
async function cursorSkillAvailable(context: AdapterContext): Promise<boolean> {
  const roots = [
    path.join(context.repoRoot, ".cursor", "skills"),
    path.join(context.repoRoot, ".agents", "skills"),
    path.join(context.repoRoot, ".claude", "skills"),
    path.join(context.home, ".cursor", "skills"),
    path.join(context.home, ".agents", "skills"),
    path.join(context.home, ".claude", "skills")
  ];
  for (const root of roots) {
    if (await directoryExists(path.join(root, BRAND.skillId))) return true;
  }
  return false;
}

const FRONTMATTER_END = "\n---\n\n";

/**
 * A rule file Myrqen owns outright, with the managed markers *after* the
 * frontmatter.
 *
 * Both editors parse the YAML block from the first byte of the file. An HTML
 * comment above it would push `---` off the first line and the rule would
 * silently lose its trigger configuration — Cursor would treat it as a manual
 * rule, which looks identical to a working install right up until nobody's rule
 * ever fires.
 */
function ownedRuleDocument(frontmatter: Record<string, string>, payload: PayloadContext): string {
  const document = frontmatterPayload(frontmatter, payload);
  const boundary = document.indexOf(FRONTMATTER_END);
  if (boundary < 0) {
    // `frontmatterPayload` always closes the block with a fence and a blank
    // line. Reaching here means that contract changed underneath this file, and
    // guessing would produce a rule file the editor cannot read.
    throw new Error("The rule payload no longer carries a frontmatter block.");
  }
  const header = document.slice(0, boundary + FRONTMATTER_END.length);
  const body = document.slice(boundary + FRONTMATTER_END.length).trim();
  return `${header}${ownedFileHeader("html")}\n${body}\n\n${provenanceLine()}\n${endMarker("html")}\n`;
}

/** What goes inside a managed region in a file Myrqen shares with the user. */
function pointerBody(payload: PayloadContext): string {
  return `${pointerPayload(payload)}\n\n${provenanceLine()}`;
}

/**
 * Plan one file Myrqen owns end to end.
 *
 * A file of the same name that carries no Myrqen marker is somebody else's
 * rule. Blocking is the only safe answer: the planner cannot ask, and silently
 * replacing a rule a team wrote would be indistinguishable from data loss.
 */
async function planOwnedFile(context: AdapterContext, target: string, contents: string): Promise<PlannedWrite> {
  const display = displayPath(target, context.repoRoot, context.home);
  const existing = await readIfPresent(target);

  if (existing === null) {
    return { path: target, displayPath: display, action: "create", contents, preservesExistingContent: false };
  }
  if (findManagedRegions(existing, "html").length === 0) {
    return {
      path: target,
      displayPath: display,
      action: "blocked",
      preservesExistingContent: true,
      reason: `a rule file of this name is already here and ${BRAND.displayName} did not write it`
    };
  }
  if (existing === contents) {
    return { path: target, displayPath: display, action: "unchanged", preservesExistingContent: false };
  }
  return { path: target, displayPath: display, action: "update", contents, preservesExistingContent: false };
}

/** Plan a managed region inside a file the user also writes in. */
async function planSharedFile(context: AdapterContext, target: string, body: string): Promise<PlannedWrite> {
  const display = displayPath(target, context.repoRoot, context.home);
  const merged = mergeManagedRegion(await readIfPresent(target), body, "html");

  if (merged.action === "conflicted") {
    return {
      path: target,
      displayPath: display,
      action: "blocked",
      preservesExistingContent: true,
      reason: `this file holds more than one ${BRAND.displayName} region; remove the extra one and link again`
    };
  }
  if (merged.action === "unchanged") {
    return {
      path: target,
      displayPath: display,
      action: "unchanged",
      preservesExistingContent: merged.preservesExistingContent
    };
  }
  return {
    path: target,
    displayPath: display,
    action: merged.action,
    contents: merged.contents,
    preservesExistingContent: merged.preservesExistingContent
  };
}

/** Uninstall for a file Myrqen owns: delete it, or refuse to touch it. */
async function planOwnedRemoval(context: AdapterContext, target: string): Promise<PlannedWrite[]> {
  const existing = await readIfPresent(target);
  if (existing === null) return [];

  const display = displayPath(target, context.repoRoot, context.home);
  if (findManagedRegions(existing, "html").length === 0) {
    return [
      {
        path: target,
        displayPath: display,
        action: "blocked",
        preservesExistingContent: true,
        reason: `${BRAND.displayName} did not write this file, so it is left alone`
      }
    ];
  }
  return [{ path: target, displayPath: display, action: "remove", preservesExistingContent: false }];
}

/** Uninstall for a shared file: take back the region and nothing else. */
async function planSharedRemoval(context: AdapterContext, target: string): Promise<PlannedWrite[]> {
  const existing = await readIfPresent(target);
  if (existing === null) return [];

  const removal = removeManagedRegion(existing, "html");
  if (!removal.removed) return [];

  const display = displayPath(target, context.repoRoot, context.home);
  // A file left holding nothing but whitespace was only ever Myrqen's, so it
  // goes with the region. Anything else is the user's and is written back.
  return removal.empty
    ? [{ path: target, displayPath: display, action: "remove", preservesExistingContent: false }]
    : [
        {
          path: target,
          displayPath: display,
          action: "remove",
          contents: removal.contents,
          preservesExistingContent: true
        }
      ];
}

/** Reconstruct one installed integration from the markers in a file. */
async function readInstalled(
  context: AdapterContext,
  adapterId: string,
  scope: Scope,
  target: string,
  sharedFile: boolean
): Promise<InstalledIntegration | null> {
  const existing = await readIfPresent(target);
  if (existing === null) return null;

  const region = findManagedRegions(existing, "html")[0];
  if (!region) return null;

  return {
    adapterId,
    scope,
    path: target,
    displayPath: displayPath(target, context.repoRoot, context.home),
    // A region written before the version was recorded is payload 1 by
    // definition; treating it as unknown would make `doctor` unable to say
    // whether relinking would change anything.
    payloadVersion: region.version ?? "1",
    sharedFile
  };
}

async function validateRuleFile(integration: InstalledIntegration): Promise<ValidationResult> {
  const existing = await readIfPresent(integration.path);
  if (existing === null) {
    return {
      health: "missing",
      detail: `${integration.displayPath} is no longer on disk.`,
      remedy: `Run "${BRAND.cliName} link".`
    };
  }

  const regions = findManagedRegions(existing, "html");
  if (regions.length === 0) {
    return {
      health: "missing",
      detail: `${integration.displayPath} no longer carries a ${BRAND.displayName} region.`,
      remedy: `Run "${BRAND.cliName} link".`
    };
  }
  if (regions.length > 1) {
    return {
      health: "conflicted",
      detail: `${integration.displayPath} carries ${regions.length} ${BRAND.displayName} regions, and the editor will read all of them.`,
      remedy: `Run "${BRAND.cliName} unlink" and then "${BRAND.cliName} link".`
    };
  }

  // A dedicated rule file that no longer opens with its YAML block still looks
  // installed from the outside, but the editor has lost the trigger that tells
  // it when to load the rule. Nothing else in the product can notice that.
  if (!integration.sharedFile && !existing.startsWith("---")) {
    return {
      health: "conflicted",
      detail: `${integration.displayPath} no longer starts with its frontmatter, so the editor cannot tell when to load it.`,
      remedy: `Run "${BRAND.cliName} link".`
    };
  }

  const version = regions[0]?.version ?? "1";
  if (version !== PAYLOAD_VERSION) {
    return {
      health: "stale",
      detail: `${integration.displayPath} carries payload v${version}; this release writes v${PAYLOAD_VERSION}.`,
      remedy: `Run "${BRAND.cliName} link".`
    };
  }

  return { health: "healthy", detail: `${integration.displayPath} is current.` };
}

/**
 * Cursor detection.
 *
 * The shell command and the headless agent binary are separate installs and
 * either one proves Cursor is here. Neither name appears on an official page —
 * they come from the shipped shell integration — so a miss costs nothing: the
 * configuration directory and the application bundle carry the verdict on their
 * own. Nothing below opens a file.
 */
/**
 * Both of Cursor's shell entry points print a version and exit.
 *
 * `cursor --version` prints the application build without opening a window, and
 * `cursor-agent --version` prints the headless agent's. Neither writes
 * configuration on a first run.
 */
const CURSOR_CLIS: readonly CommandProbe[] = Object.freeze([
  { command: "cursor", flag: "--version" },
  { command: "cursor-agent", flag: "--version" }
]);

/** `windsurf --version` behaves the same way as Cursor's. */
const WINDSURF_CLI: CommandProbe = { command: "windsurf", flag: "--version" };

async function detectCursor(context: AdapterContext): Promise<DetectionResult> {
  const signals: DetectionSignal[] = [];
  let version: string | undefined;

  for (const probe of CURSOR_CLIS) {
    const executable = await whichExecutable(probe.command, context);
    if (!executable) continue;
    signals.push({ kind: "executable", detail: `${probe.command} on PATH` });
    version ??= await probeVersion(context, probe, executable, signals);
  }

  if (await applicationInstalled([CURSOR], context)) {
    signals.push({ kind: "application", detail: `${CURSOR} application` });
  }

  const configuration = await configDirectorySignal(".cursor", context, `${CURSOR} configuration`);
  if (configuration) signals.push(configuration);

  const project = await projectFileSignal(path.join(".cursor", "rules"), context);
  if (project) signals.push(project);

  return verdict(signals, version);
}

/**
 * Windsurf detection.
 *
 * `~/.codeium/windsurf` is the signal to trust: it is the directory the
 * documented global rules file lives in, so its existence is corroborated by
 * the format itself. The executable and application names are not on an
 * official page and are treated as corroboration, never as a prerequisite.
 */
async function detectWindsurf(context: AdapterContext): Promise<DetectionResult> {
  const signals: DetectionSignal[] = [];
  let version: string | undefined;

  const executable = await whichExecutable("windsurf", context);
  if (executable) {
    signals.push({ kind: "executable", detail: "windsurf on PATH" });
    version = await probeVersion(context, WINDSURF_CLI, executable, signals);
  }

  if (await applicationInstalled([WINDSURF], context)) {
    signals.push({ kind: "application", detail: `${WINDSURF} application` });
  }

  const configuration = await configDirectorySignal(
    path.join(".codeium", "windsurf"),
    context,
    `${WINDSURF} configuration`
  );
  if (configuration) signals.push(configuration);

  const project = await projectFileSignal(path.join(".windsurf", "rules"), context);
  if (project) signals.push(project);

  return verdict(signals, version);
}

function cursorNotes(skillAvailable: boolean): string[] {
  return [
    skillAvailable
      ? `Invoke with /${BRAND.skillId} in the Cursor agent, or "${BRAND.cliName} auto" from a terminal.`
      : `Invoke with "${BRAND.cliName} auto" from a terminal; the rule tells Cursor when to reach for it.`,
    "The rule loads on demand, so it costs nothing on the conversations that are not about security.",
    `${CURSOR} also reads AGENTS.md at the repository root. ${BRAND.displayName} leaves that file to its own AGENTS.md integration.`
  ];
}

const WINDSURF_PROJECT_NOTES = [
  `Invoke with "${BRAND.cliName} auto" from a terminal; Cascade loads the rule when the description matches.`,
  "Written to .windsurf/rules/, which every released build reads — new ones as the fallback for .devin/rules/."
];

const WINDSURF_GLOBAL_NOTES = [
  `global_rules.md is shared with your own global rules. ${BRAND.displayName} owns only the region between its markers and leaves the rest byte for byte.`,
  `Invoke with "${BRAND.cliName} auto" from a terminal.`
];

export const cursorAdapter: AgentAdapter = {
  id: "cursor",
  displayName: CURSOR,
  documentation: "https://cursor.com/docs/context/rules",
  primitive: "rules_file",
  platforms: PLATFORMS,
  probes: CURSOR_CLIS,

  detect: detectCursor,

  /**
   * Project only, on purpose.
   *
   * Cursor's User Rules are edited in the application's settings and have no
   * documented file behind them. The storage that backs them can be found by
   * opening Cursor's own database, which is exactly the kind of reverse
   * engineering that turns a setup tool into something a user cannot trust —
   * and which breaks the first time Cursor changes its schema.
   */
  supportedScopes(): Scope[] {
    return ["project"];
  },

  async createInstallPlan(context, scope) {
    if (scope !== "project") {
      return {
        adapterId: cursorAdapter.id,
        displayName: CURSOR,
        scope,
        writes: [],
        notes: [
          `${CURSOR} user rules are edited inside the app and have no documented file, so ${BRAND.displayName} installs them per project.`
        ]
      };
    }

    const skillAvailable = await cursorSkillAvailable(context);
    const payload: PayloadContext = skillAvailable
      ? { skillAvailable: true, slashCommand: BRAND.skillId }
      : { skillAvailable: false };

    return {
      adapterId: cursorAdapter.id,
      displayName: CURSOR,
      scope,
      writes: [await planOwnedFile(context, cursorRulePath(context), ownedRuleDocument(CURSOR_FRONTMATTER, payload))],
      notes: cursorNotes(skillAvailable)
    };
  },

  async installed(context) {
    const found = await readInstalled(context, cursorAdapter.id, "project", cursorRulePath(context), false);
    return found ? [found] : [];
  },

  async validate(_context, integration) {
    return validateRuleFile(integration);
  },

  async createUninstallPlan(context, scope) {
    return {
      adapterId: cursorAdapter.id,
      displayName: CURSOR,
      scope,
      writes: scope === "project" ? await planOwnedRemoval(context, cursorRulePath(context)) : [],
      notes: []
    };
  }
};

export const windsurfAdapter: AgentAdapter = {
  id: "windsurf",
  displayName: WINDSURF,
  documentation: "https://docs.devin.ai/desktop/cascade/memories",
  primitive: "rules_file",
  platforms: PLATFORMS,
  probes: [WINDSURF_CLI],

  detect: detectWindsurf,

  /** Both scopes are documented: a rules directory per project, one file per user. */
  supportedScopes(): Scope[] {
    return ["project", "global"];
  },

  async createInstallPlan(context, scope) {
    if (scope === "global") {
      return {
        adapterId: windsurfAdapter.id,
        displayName: WINDSURF,
        scope,
        writes: [await planSharedFile(context, windsurfGlobalRulesPath(context), pointerBody({ skillAvailable: false }))],
        notes: WINDSURF_GLOBAL_NOTES
      };
    }

    return {
      adapterId: windsurfAdapter.id,
      displayName: WINDSURF,
      scope,
      writes: [
        await planOwnedFile(
          context,
          windsurfProjectRulePath(context),
          // Windsurf's on-demand primitive is a workflow, not a skill, and
          // Myrqen does not install one, so the pointer names the CLI rather
          // than a slash command the editor would not answer.
          ownedRuleDocument(WINDSURF_FRONTMATTER, { skillAvailable: false })
        )
      ],
      notes: WINDSURF_PROJECT_NOTES
    };
  },

  async installed(context) {
    const found = await Promise.all([
      readInstalled(context, windsurfAdapter.id, "project", windsurfProjectRulePath(context), false),
      readInstalled(context, windsurfAdapter.id, "global", windsurfGlobalRulesPath(context), true)
    ]);
    return found.filter((entry): entry is InstalledIntegration => entry !== null);
  },

  async validate(_context, integration) {
    return validateRuleFile(integration);
  },

  async createUninstallPlan(context, scope) {
    return {
      adapterId: windsurfAdapter.id,
      displayName: WINDSURF,
      scope,
      writes:
        scope === "project"
          ? await planOwnedRemoval(context, windsurfProjectRulePath(context))
          : await planSharedRemoval(context, windsurfGlobalRulesPath(context)),
      notes: []
    };
  }
};
