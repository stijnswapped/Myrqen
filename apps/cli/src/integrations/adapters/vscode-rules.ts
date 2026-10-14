import path from "node:path";
import { BRAND } from "@myrqen/brand";
import {
  PAYLOAD_VERSION,
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
 * Cline, Roo Code, and Continue.
 *
 * Three VS Code extensions that arrived at the same shape independently: a
 * directory of Markdown rule files, every file in it read at the start of a
 * task. That shape is the reason these three share a file. Because the format
 * is a directory and not one shared document, Myrqen writes a file of its own
 * and owns it outright — no other tool's rules are ever parsed, rewritten, or
 * reordered, and uninstalling is deleting one file the user can name.
 *
 * All three get the *pointer* payload, not the method. A rules directory is
 * read at the top of every conversation in the project, including the ones
 * about CSS, so what Myrqen leaves here is a permanent tax on unrelated work.
 * None of the three exposes an on-demand primitive Myrqen installs today, so
 * the pointer sends the user to the CLI, which loads the method on demand.
 */

/** Every target here is Markdown, so the markers are HTML comments. */
const STYLE: MarkerStyle = "html";

/** All three ship as VS Code extensions and run wherever VS Code does. */
const PLATFORMS: readonly NodeJS.Platform[] = ["darwin", "linux", "win32"];

/** The one file Myrqen owns inside somebody else's rules directory. */
const RULE_FILE = `${BRAND.cliName}.md`;

/**
 * Continue is the only one of the three whose rule files carry frontmatter, and
 * `frontmatterPayload()` cannot be used for it: that helper frames a whole file
 * with no managed region, and `status`, `doctor`, and `unlink` find this file by
 * its region. So the frontmatter is written above the region instead, which is
 * also the only correct order — YAML frontmatter must be the first bytes of the
 * file, and an HTML comment above it would stop Continue parsing the header at
 * all.
 *
 * `alwaysApply: true` is deliberate and is exactly why the payload is the short
 * pointer: the file is included in every request whether or not the user is
 * doing security work.
 */
const CONTINUE_FRONTMATTER = [
  "---",
  `name: ${BRAND.displayName} security assessment`,
  `description: When and how to run a ${BRAND.displayName} security assessment of this project.`,
  "alwaysApply: true",
  "---"
].join("\n");

/** One file Myrqen writes, plus what the format demands around it. */
interface RuleFileTarget {
  /** Absolute path of the file. */
  path: string;
  /** Frontmatter that must sit above the managed region, or null when the format has none. */
  header: string | null;
  /** Something about this particular target the user has to be told, or null. */
  note: string | null;
}

function ruleBody(): string {
  return `${pointerPayload({ skillAvailable: false })}\n\n${provenanceLine()}`;
}

/**
 * Whether this file holds anything Myrqen did not write.
 *
 * The answer decides two things: whether the plan tells the user their content
 * is being preserved, and whether uninstalling deletes the file or only cuts the
 * region out of it. Frontmatter Myrqen wrote itself does not count as the
 * user's — otherwise Continue's own rule file could never be removed cleanly.
 */
function holdsForeignContent(existing: string, header: string | null): boolean {
  const leftover = removeManagedRegion(existing, STYLE).contents.replace(/\r\n/g, "\n").trim();
  if (leftover.length === 0) return false;
  return header === null || leftover !== header.trim();
}

/**
 * Compute the write for one rule file. Nothing here touches the disk except to
 * read it: the plan is printed and confirmed before a separate applier runs it.
 */
async function planWrite(target: RuleFileTarget, context: AdapterContext): Promise<PlannedWrite> {
  const shown = displayPath(target.path, context.repoRoot, context.home);
  const existing = await readIfPresent(target.path);

  if (existing === null || existing.trim().length === 0) {
    const block = mergeManagedRegion(null, ruleBody(), STYLE).contents;
    return {
      path: target.path,
      displayPath: shown,
      action: "create",
      contents: target.header ? `${target.header}\n${block}` : block,
      preservesExistingContent: false
    };
  }

  const merged = mergeManagedRegion(existing, ruleBody(), STYLE);
  if (merged.action === "conflicted") {
    return {
      path: target.path,
      displayPath: shown,
      action: "blocked",
      preservesExistingContent: true,
      reason: `${shown} already holds more than one ${BRAND.displayName} region, and guessing which one is current would be worse than stopping.`
    };
  }

  const foreign = holdsForeignContent(existing, target.header);
  if (merged.action === "unchanged") {
    return { path: target.path, displayPath: shown, action: "unchanged", preservesExistingContent: foreign };
  }

  return {
    path: target.path,
    displayPath: shown,
    action: merged.action === "merge" ? "merge" : "update",
    contents: merged.contents,
    preservesExistingContent: foreign
  };
}

/**
 * Compute the removal for one rule file.
 *
 * A file that is nothing but Myrqen's region goes away entirely; a file that
 * also holds the user's own instructions keeps them and loses only the region.
 * The rules directory around the file is never part of the plan — the other
 * rules in it belong to the user.
 */
async function planRemoval(target: RuleFileTarget, context: AdapterContext): Promise<PlannedWrite> {
  const shown = displayPath(target.path, context.repoRoot, context.home);
  const existing = await readIfPresent(target.path);
  if (existing === null) {
    return { path: target.path, displayPath: shown, action: "unchanged", preservesExistingContent: false };
  }

  const stripped = removeManagedRegion(existing, STYLE);
  if (!stripped.removed) {
    return { path: target.path, displayPath: shown, action: "unchanged", preservesExistingContent: true };
  }

  if (!holdsForeignContent(existing, target.header)) {
    return { path: target.path, displayPath: shown, action: "remove", preservesExistingContent: false };
  }
  return {
    path: target.path,
    displayPath: shown,
    action: "remove",
    contents: stripped.contents,
    preservesExistingContent: true
  };
}

/** What is on disk, read back from the marker rather than from a database. */
async function installedFrom(
  adapterId: string,
  scope: Scope,
  target: RuleFileTarget,
  context: AdapterContext
): Promise<InstalledIntegration | null> {
  const existing = await readIfPresent(target.path);
  if (existing === null) return null;
  const region = findManagedRegions(existing.replace(/\r\n/g, "\n"), STYLE)[0];
  if (!region) return null;
  return {
    adapterId,
    scope,
    path: target.path,
    displayPath: displayPath(target.path, context.repoRoot, context.home),
    // A region with no version predates versioned markers. "0" sorts below every
    // released payload, so validate() calls it stale and the user is offered the
    // one command that fixes it.
    payloadVersion: region.version ?? "0",
    sharedFile: holdsForeignContent(existing, target.header)
  };
}

async function validateRuleFile(integration: InstalledIntegration): Promise<ValidationResult> {
  const existing = await readIfPresent(integration.path);
  if (existing === null) {
    return {
      health: "missing",
      detail: `${integration.displayPath} is no longer on disk.`,
      remedy: `Run "${BRAND.cliName} link" to write it again.`
    };
  }

  const regions = findManagedRegions(existing.replace(/\r\n/g, "\n"), STYLE);
  if (regions.length === 0) {
    return {
      health: "missing",
      detail: `${integration.displayPath} exists but no longer contains a ${BRAND.displayName} region.`,
      remedy: `Run "${BRAND.cliName} link" to write it again.`
    };
  }
  if (regions.length > 1) {
    return {
      health: "conflicted",
      detail: `${integration.displayPath} contains ${regions.length} ${BRAND.displayName} regions, so the agent reads the same instructions twice.`,
      remedy: `Run "${BRAND.cliName} unlink" and then "${BRAND.cliName} link".`
    };
  }

  const version = regions[0]?.version ?? null;
  if (version !== PAYLOAD_VERSION) {
    return {
      health: "stale",
      detail: `${integration.displayPath} carries payload ${version ? `v${version}` : "from before payloads were versioned"}; this release writes v${PAYLOAD_VERSION}.`,
      remedy: `Run "${BRAND.cliName} link" to bring it up to date.`
    };
  }

  return { health: "healthy", detail: `${integration.displayPath} is current (payload v${PAYLOAD_VERSION}).` };
}

interface RuleAdapterSpec {
  id: string;
  displayName: string;
  documentation: string;
  /** Only scopes the vendor documents. */
  scopes: readonly Scope[];
  detect: (context: AdapterContext) => Promise<DetectionResult>;
  target: (context: AdapterContext, scope: Scope) => Promise<RuleFileTarget>;
  /** How the user reaches Myrqen once the file is in place. */
  invocation: string;
  /** Commands this agent's detection is willing to execute; usually none. */
  probes?: readonly CommandProbe[];
}

/**
 * The three adapters differ only in where their file goes and how the agent is
 * detected, so the interface is implemented once here. Anything that is not
 * genuinely shared — Cline's legacy single-file form, Continue's frontmatter —
 * lives in that adapter's own target resolver, not in a flag threaded through
 * this function.
 */
function ruleAdapter(spec: RuleAdapterSpec): AgentAdapter {
  return {
    id: spec.id,
    displayName: spec.displayName,
    documentation: spec.documentation,
    primitive: "rules_file",
    platforms: PLATFORMS,
    ...(spec.probes ? { probes: spec.probes } : {}),
    detect: spec.detect,
    supportedScopes: () => [...spec.scopes],

    async createInstallPlan(context: AdapterContext, scope: Scope): Promise<InstallPlan> {
      const target = await spec.target(context, scope);
      const write = await planWrite(target, context);
      return {
        adapterId: spec.id,
        displayName: spec.displayName,
        scope,
        writes: [write],
        notes: target.note ? [spec.invocation, target.note] : [spec.invocation]
      };
    },

    async installed(context: AdapterContext): Promise<InstalledIntegration[]> {
      const found: InstalledIntegration[] = [];
      for (const scope of spec.scopes) {
        const entry = await installedFrom(spec.id, scope, await spec.target(context, scope), context);
        if (entry) found.push(entry);
      }
      return found;
    },

    async validate(_context: AdapterContext, integration: InstalledIntegration): Promise<ValidationResult> {
      return validateRuleFile(integration);
    },

    async createUninstallPlan(context: AdapterContext, scope: Scope): Promise<InstallPlan> {
      const target = await spec.target(context, scope);
      return {
        adapterId: spec.id,
        displayName: spec.displayName,
        scope,
        writes: [await planRemoval(target, context)],
        notes: []
      };
    }
  };
}

/**
 * Look for the stable extension first and the nightly build only if that misses.
 * Almost nobody runs the nightly, and the first question usually answers it.
 */
async function vscodeExtension(
  stable: string,
  nightly: string,
  context: AdapterContext
): Promise<DetectionSignal | null> {
  return (await editorExtension("code", stable, context)) ?? (await editorExtension("code", nightly, context));
}

/** `cline --version` prints the CLI version and exits. */
const CLINE_CLI: CommandProbe = { command: "cline", flag: "--version" };

/** `cn --version` does the same for Continue's CLI. */
const CONTINUE_CLI: CommandProbe = { command: "cn", flag: "--version" };

async function detectCline(context: AdapterContext): Promise<DetectionResult> {
  const signals: DetectionSignal[] = [];

  const extension = await vscodeExtension("saoudrizwan.claude-dev", "saoudrizwan.cline-nightly", context);
  if (extension) signals.push(extension);

  let version: string | undefined;
  const executable = await whichExecutable("cline", context);
  if (executable) {
    signals.push({ kind: "executable", detail: executable });
    version = await probeVersion(context, CLINE_CLI, executable, signals);
  }

  // Two documented directories, because the CLI and the extension do not share
  // one: `~/.cline` holds skills and CLI state, `~/Documents/Cline` holds the
  // global rules this adapter writes.
  for (const [relative, label] of [
    [".cline", "Cline"],
    [path.join("Documents", "Cline"), "Cline global rules"]
  ] as const) {
    const signal = await configDirectorySignal(relative, context, label);
    if (signal) signals.push(signal);
  }

  const project = await projectFileSignal(".clinerules", context);
  if (project) signals.push(project);

  return verdict(signals, version);
}

/**
 * Cline's global rules live under the user's Documents folder on every platform
 * it documents, with `~/Cline/Rules` as a second Linux location. The alternate
 * is used only when it actually exists, so a fresh Linux install still gets the
 * primary path rather than a directory nothing reads.
 */
async function clineGlobalRulesDirectory(context: AdapterContext): Promise<string> {
  const documents = path.join(context.home, "Documents", "Cline", "Rules");
  if (context.platform === "linux" && !(await directoryExists(documents))) {
    const alternate = path.join(context.home, "Cline", "Rules");
    if (await directoryExists(alternate)) return alternate;
  }
  return documents;
}

/**
 * `.clinerules` is documented as *either* a directory whose files are all read
 * *or* a single legacy file. Turning one into the other would be Myrqen
 * restructuring a user's configuration behind their back, so the shape already
 * on disk decides: a directory gets a file of Myrqen's own, and a legacy file
 * gets a marked region appended to it with everything else left byte for byte.
 */
async function clineTarget(context: AdapterContext, scope: Scope): Promise<RuleFileTarget> {
  if (scope === "global") {
    return { path: path.join(await clineGlobalRulesDirectory(context), RULE_FILE), header: null, note: null };
  }

  const root = path.join(context.repoRoot, ".clinerules");
  if ((await pathExists(root)) && !(await directoryExists(root))) {
    return {
      path: root,
      header: null,
      note: `.clinerules is a single file in this project, not a directory, so ${BRAND.displayName} adds a marked section to it instead of writing .clinerules/${RULE_FILE}. Everything already in that file stays exactly as it is.`
    };
  }
  return { path: path.join(root, RULE_FILE), header: null, note: null };
}

async function detectRoo(context: AdapterContext): Promise<DetectionResult> {
  const signals: DetectionSignal[] = [];

  const extension = await vscodeExtension("RooVeterinaryInc.roo-cline", "RooVeterinaryInc.roo-code-nightly", context);
  if (extension) signals.push(extension);

  const configDirectory = await configDirectorySignal(".roo", context, "Roo Code");
  if (configDirectory) signals.push(configDirectory);

  // Either project marker counts: `.roo` is the current directory form and
  // `.roorules` the legacy single file, and a repository configured by a
  // colleague is exactly what `project_only` confidence is for.
  for (const relative of [".roo", ".roorules"]) {
    const signal = await projectFileSignal(relative, context);
    if (signal) {
      signals.push(signal);
      break;
    }
  }

  return verdict(signals);
}

async function rooTarget(context: AdapterContext, scope: Scope): Promise<RuleFileTarget> {
  const root = scope === "global" ? context.home : context.repoRoot;
  return { path: path.join(root, ".roo", "rules", RULE_FILE), header: null, note: null };
}

async function detectContinue(context: AdapterContext): Promise<DetectionResult> {
  const signals: DetectionSignal[] = [];

  const extension = await editorExtension("code", "Continue.continue", context);
  if (extension) signals.push(extension);

  let version: string | undefined;
  const configDirectory = await configDirectorySignal(".continue", context, "Continue");
  if (configDirectory) {
    signals.push(configDirectory);
    // Continue's CLI is called `cn`. A two-letter name on PATH is not by itself
    // evidence of anything, so it is only looked for when Continue's own
    // configuration directory is already there to corroborate it — and that
    // gate is why the version probe stays here rather than moving somewhere
    // more generic: whatever else answers to `cn` on this machine, Myrqen has
    // no business launching it.
    const executable = await whichExecutable("cn", context);
    if (executable) {
      signals.push({ kind: "executable", detail: executable });
      version = await probeVersion(context, CONTINUE_CLI, executable, signals);
    }
  }

  const project = await projectFileSignal(".continue", context);
  if (project) signals.push(project);

  return verdict(signals, version);
}

async function continueTarget(context: AdapterContext, scope: Scope): Promise<RuleFileTarget> {
  const root = scope === "global" ? context.home : context.repoRoot;
  return {
    path: path.join(root, ".continue", "rules", RULE_FILE),
    header: CONTINUE_FRONTMATTER,
    note: null
  };
}

/**
 * Cline reads every `.md` and `.txt` file in `.clinerules/`, and its global
 * rules live under Documents rather than a dot-directory.
 * Verified against https://docs.cline.bot/features/cline-rules on 2026-08-20.
 */
export const clineAdapter: AgentAdapter = ruleAdapter({
  id: "cline",
  displayName: "Cline",
  documentation: "https://docs.cline.bot/features/cline-rules",
  scopes: ["project", "global"],
  detect: detectCline,
  probes: [CLINE_CLI],
  target: clineTarget,
  invocation: `Ask Cline for a security review of this project, or run "${BRAND.cliName} auto" from any terminal.`
});

/**
 * Roo Code reads `.roo/rules/` in the workspace and `~/.roo/rules/` for the
 * user, with no frontmatter documented for rule files — so none is written.
 * Verified against https://roocodeinc.github.io/Roo-Code/features/custom-instructions
 * on 2026-08-20.
 */
export const rooAdapter: AgentAdapter = ruleAdapter({
  id: "roo-code",
  displayName: "Roo Code",
  documentation: "https://roocodeinc.github.io/Roo-Code/features/custom-instructions",
  scopes: ["project", "global"],
  detect: detectRoo,
  target: rooTarget,
  invocation: `Ask Roo Code for a security review of this project, or run "${BRAND.cliName} auto" from any terminal.`
});

/**
 * Continue loads `.continue/rules/*.md` in lexicographic order, project and
 * user directories alike, and its frontmatter fields are `name`, `description`,
 * `globs`, `regex`, and `alwaysApply`.
 * Verified against https://docs.continue.dev/customize/deep-dives/rules on 2026-08-20.
 */
export const continueAdapter: AgentAdapter = ruleAdapter({
  id: "continue",
  displayName: "Continue",
  documentation: "https://docs.continue.dev/customize/deep-dives/rules",
  scopes: ["project", "global"],
  detect: detectContinue,
  probes: [CONTINUE_CLI],
  target: continueTarget,
  invocation: `Ask Continue for a security review of this project, or run "${BRAND.cliName} auto" from any terminal.`
});
