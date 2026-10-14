import fs from "node:fs/promises";
import path from "node:path";
import type {
  AdapterContext,
  CommandProbe,
  DetectionConfidence,
  DetectionResult,
  DetectionSignal
} from "./types.js";
import { directoryExists, displayPath, pathExists } from "./managed.js";
import { probeListing } from "./probe.js";

/**
 * Environment detection.
 *
 * The rules this module exists to enforce:
 *
 *  - Execute nothing to reach a verdict. Every signal below is established by
 *    reading the filesystem: an executable's presence on `PATH`, an application
 *    bundle, an editor's extensions directory, a documented configuration
 *    directory. Launching an agent's own CLI is not a free question — one of
 *    them bootstraps itself on first run — so a verdict is never allowed to
 *    depend on one. See `probe.ts` for the whole of that argument.
 *  - More than one kind of signal, wherever the platform offers one. A folder
 *    named `.continue` proves someone once had Continue; the `cn` binary sitting
 *    on `PATH` beside it proves it is installed now.
 *  - Never read a secret. Detection asks whether a path exists. It does not open
 *    credential stores, token files, chat databases, or any configuration whose
 *    contents are not the specific fact being established.
 *  - Never block. The one place that may still execute something is
 *    time-bounded, and a machine with a broken editor install must still reach
 *    the end of `myrqen link`.
 */

/** Files under these names are credentials, whatever directory they sit in. */
const NEVER_READ = /(^|[/\\])(\.env(\..*)?|credentials?(\.json)?|auth\.json|token(s)?\.json|session(s)?\.json|.*\.key|.*\.pem|id_rsa.*|cookies?\.sqlite|history\.db|conversations?\.(db|json))$/i;

export function isSensitivePath(target: string): boolean {
  return NEVER_READ.test(target);
}

/**
 * Resolve an executable the way the platform does, by reading `PATH` — and by
 * starting no process of any kind.
 *
 * This used to shell out: `where.exe` on Windows, `/usr/bin/env sh -c
 * "command -v <name>"` elsewhere. That was two subprocesses per candidate name
 * on every run of `link`, `status`, and `doctor`, to answer a question the
 * filesystem answers directly, and it put a user-influenced name one quoting
 * mistake away from a shell. Walking `PATH` here is faster, is not a
 * command-injection surface at all, and — the reason this change exists — means
 * an agent's *presence* is established without executing anything, so the
 * confidence verdict never depends on launching somebody else's program.
 *
 * `PATH` comes from the injected environment rather than from `process.env`, so
 * a fixture describing a machine with three editors on it is the machine
 * detection actually sees.
 */
export async function whichExecutable(name: string, context: AdapterContext): Promise<string | null> {
  if (!/^[A-Za-z0-9._-]+$/.test(name)) return null;

  const windows = context.platform === "win32";
  // Windows environment blocks are case-insensitive and a real one arrives as
  // `Path` about as often as `PATH`; a fixture object is neither, so both names
  // are asked for.
  const raw = windows ? (context.env.PATH ?? context.env.Path ?? context.env.path) : context.env.PATH;
  if (!raw) return null;

  const candidates = windows ? windowsCandidates(name, context.env) : [name];

  for (const entry of raw.split(windows ? ";" : ":")) {
    // A quoted `PATH` entry is ordinary on Windows, and an empty one means the
    // working directory, which is not somewhere Myrqen goes looking for agents.
    const directory = entry.replace(/^"|"$/g, "").trim();
    if (!directory) continue;
    for (const candidate of candidates) {
      const full = path.join(directory, candidate);
      if (await isExecutableFile(full, windows)) return full;
    }
  }
  return null;
}

/** `PATHEXT` decides what counts as runnable on Windows; the bare name may too. */
function windowsCandidates(name: string, env: NodeJS.ProcessEnv): string[] {
  const extensions = (env.PATHEXT ?? env.Pathext ?? ".COM;.EXE;.BAT;.CMD")
    .split(";")
    .map((extension) => extension.trim())
    .filter(Boolean);
  return [name, ...extensions.map((extension) => `${name}${extension.toLowerCase()}`)];
}

/**
 * A real file the current user may run.
 *
 * `stat` first, because `access(X_OK)` says yes to a directory, and a directory
 * called `cursor` sitting on `PATH` is not Cursor. On Windows there is no
 * executable bit, so the extension list is what decides and existence is enough.
 */
async function isExecutableFile(target: string, windows: boolean): Promise<boolean> {
  try {
    const info = await fs.stat(target);
    if (!info.isFile()) return false;
    if (windows) return true;
    await fs.access(target, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

/** macOS application bundles and their Windows/Linux equivalents. */
export async function applicationInstalled(names: string[], context: AdapterContext): Promise<string | null> {
  const { platform, home, env } = context;
  const roots =
    platform === "darwin"
      ? ["/Applications", path.join(home, "Applications")]
      : platform === "win32"
        ? [
            env.LOCALAPPDATA ? path.join(env.LOCALAPPDATA, "Programs") : null,
            env.ProgramFiles ?? null,
            env["ProgramFiles(x86)"] ?? null
          ].filter((value): value is string => Boolean(value))
        : ["/usr/share/applications", path.join(home, ".local", "share", "applications"), "/opt"];

  for (const root of roots) {
    for (const name of names) {
      const candidate = path.join(root, platform === "darwin" ? `${name}.app` : name);
      if (await pathExists(candidate)) return candidate;
    }
  }
  return null;
}

/**
 * `code --list-extensions` and its equivalents in the VS Code forks.
 *
 * Declared here rather than per adapter because it is one fact about one family
 * of programs: the flag prints the installed extension ids and exits, and every
 * fork inherited it. No adapter needs to restate that.
 */
const EXTENSION_LISTING: CommandProbe = { command: "code", flag: "--list-extensions" };

/**
 * Extensions installed in a VS Code-compatible editor.
 *
 * The order here is the whole point, and it used to be the other way round. The
 * editor's own CLI gives the authoritative answer, but asking for it launches
 * Electron — around a second of CPU, on every run, per editor, for a question
 * that is usually already answered by a directory listing. So the extensions
 * directory is read first and, when it answers, nothing is executed at all.
 *
 * The CLI is only consulted when the directory did not answer *and* this run
 * permits execution. That leaves one honest gap: an editor started with a
 * non-default `--extensions-dir` and probing turned off is reported one
 * confidence level lower rather than being launched to find out. A missing
 * version string is a cosmetic loss; a missing extension is a real one, so the
 * gap is named in the README instead of being closed by executing something.
 */
export async function editorExtension(
  editorCommand: string,
  extensionId: string,
  context: AdapterContext
): Promise<DetectionSignal | null> {
  const extensionsRoot = path.join(context.home, editorExtensionsDirectory(editorCommand), "extensions");
  if (await directoryExists(extensionsRoot)) {
    const entries = await fs.readdir(extensionsRoot).catch(() => [] as string[]);
    const prefix = `${extensionId.toLowerCase()}-`;
    if (entries.some((entry) => entry.toLowerCase().startsWith(prefix))) {
      return { kind: "extension", detail: `${extensionId} in ${editorCommand}` };
    }
  }

  const executable = await whichExecutable(editorCommand, context);
  if (!executable) return null;
  // The editor being on PATH is itself a signal that executed nothing, which is
  // what earns the right to ask it a question.
  const onPath: DetectionSignal[] = [{ kind: "executable", detail: `${editorCommand} on PATH` }];
  const listed = await probeListing(context, { ...EXTENSION_LISTING, command: editorCommand }, executable, onPath);
  if (listed && listed.toLowerCase().split(/\r?\n/).some((line) => line.trim() === extensionId.toLowerCase())) {
    return { kind: "extension", detail: `${extensionId} in ${editorCommand} (from its extension listing)` };
  }
  return null;
}

function editorExtensionsDirectory(editorCommand: string): string {
  switch (editorCommand) {
    case "cursor":
      return ".cursor";
    case "windsurf":
      return ".windsurf";
    case "code-insiders":
      return ".vscode-insiders";
    default:
      return ".vscode";
  }
}

/** A documented configuration directory under the user's home. */
export async function configDirectorySignal(
  relative: string,
  context: AdapterContext,
  label = relative
): Promise<DetectionSignal | null> {
  const target = path.join(context.home, relative);
  if (!(await directoryExists(target))) return null;
  return { kind: "config_directory", detail: `${label} at ${displayPath(target, context.repoRoot, context.home)}` };
}

/** A file that exists inside the project being linked. */
export async function projectFileSignal(relative: string, context: AdapterContext): Promise<DetectionSignal | null> {
  const target = path.join(context.repoRoot, relative);
  if (!(await pathExists(target))) return null;
  return { kind: "project_config", detail: relative };
}

/**
 * Turn a set of signals into a verdict.
 *
 * An executable, an application bundle, or an editor extension each proves the
 * agent is installed. A configuration directory alone means someone had it; two
 * weak signals together are as good as one strong one. A project file on its own
 * proves only that this repository was configured for it, possibly by a
 * colleague on a different machine, which is exactly what `project_only` says.
 *
 * `version` is carried through and weighed by nothing. It is absent on most
 * runs by design, and a verdict that moved when it appeared would mean the
 * confidence ladder had quietly become a reason to launch other people's
 * programs.
 */
export function verdict(signals: DetectionSignal[], version?: string): DetectionResult {
  const strong = signals.filter((signal) => signal.kind === "executable" || signal.kind === "extension");
  // An installed desktop application is real evidence, but not of the same
  // thing: shipping the chat app is not shipping the coding agent, and grading
  // it as proof pre-ticked installs on machines that had only the app.
  const supporting = signals.filter((signal) => signal.kind === "application");
  const weak = signals.filter(
    (signal) =>
      signal.kind === "config_directory" ||
      signal.kind === "config_file" ||
      signal.kind === "package_manager" ||
      signal.kind === "environment_variable"
  );
  const projectOnly = signals.filter((signal) => signal.kind === "project_config");

  // Two weak signals only add up when they are two different *kinds* of fact.
  // `CODEX_HOME` and the directory it names are one fact stated twice, and
  // counting it twice promoted an uninstalled agent to `confirmed`.
  const distinctWeakKinds = new Set(weak.map((signal) => signal.kind)).size;

  let confidence: DetectionConfidence = "absent";
  if (strong.length > 0) confidence = "confirmed";
  else if (supporting.length > 0 && weak.length > 0) confidence = "confirmed";
  else if (distinctWeakKinds >= 2) confidence = "confirmed";
  else if (weak.length > 0 || supporting.length > 0) confidence = "probable";
  else if (projectOnly.length > 0) confidence = "project_only";

  return {
    detected: confidence !== "absent",
    confidence,
    signals,
    ...(version ? { version } : {})
  };
}

export const absent: DetectionResult = { detected: false, confidence: "absent", signals: [] };
