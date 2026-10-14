import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { BRAND } from "@myrqen/brand";

/**
 * Managed regions and safe writes.
 *
 * The hard requirement this file exists to satisfy: Myrqen never clobbers a
 * user's configuration. When a format supports a dedicated file, an adapter
 * writes one and owns it entirely. When the format is a single shared file —
 * `AGENTS.md`, `CLAUDE.md`, `.github/copilot-instructions.md` — Myrqen owns a
 * marked region inside it and touches nothing else, including the parts of the
 * file it cannot parse.
 */

/**
 * Payload revision.
 *
 * Bumped when the *content* Myrqen writes changes in a way an existing install
 * should pick up. `myrqen link` run again rewrites a managed region whose
 * version is older and leaves an identical one alone, which is what makes the
 * command idempotent across releases as well as within one.
 */
export const PAYLOAD_VERSION = "2";

/**
 * The provenance file Myrqen leaves inside a skill directory it installed.
 *
 * Defined once, here, because it is the only thing that tells a later run
 * whether the bundle on disk is Myrqen's own work or a directory that merely
 * happens to share the name. Two adapters write skill bundles — Claude Code's,
 * and the shared planner the Codex, Kiro, and OpenCode adapters use — and a
 * second spelling of this name in either of them would make one of them refuse
 * to update what the other installed.
 */
export const SKILL_MARKER_FILE = ".myrqen-managed.json";

const START = `myrqen:start`;
const END = `myrqen:end`;

/** Comment syntaxes, so a marker never breaks the file it lives in. */
export type MarkerStyle = "html" | "hash" | "slash" | "semicolon";

const MARKERS: Record<MarkerStyle, { open: (body: string) => string }> = {
  html: { open: (body) => `<!-- ${body} -->` },
  hash: { open: (body) => `# ${body}` },
  slash: { open: (body) => `// ${body}` },
  semicolon: { open: (body) => `; ${body}` }
};

export function startMarker(style: MarkerStyle, version = PAYLOAD_VERSION): string {
  return MARKERS[style].open(`${START} v${version}`);
}

export function endMarker(style: MarkerStyle): string {
  return MARKERS[style].open(END);
}

/**
 * Matches a managed region of any version, in any of the comment styles.
 *
 * Both markers are anchored to a line of their own. Without the anchors, a
 * user's file that merely *mentions* the opening marker — a README explaining
 * what Myrqen writes, a fenced example, a changelog entry — is matched as the
 * start of Myrqen's region, and the next `link` replaces everything from that
 * sentence down to the real end marker. The mention is far more likely in
 * exactly the kind of file this tool edits, and the loss is silent: the
 * duplicate-region guard never fires, because the real opening marker was
 * swallowed inside the over-long match.
 */
function regionPattern(style: MarkerStyle): RegExp {
  const open = escapeRegExp(MARKERS[style].open("@@")).replace("@@", `${START}(?:\\s+v([0-9A-Za-z.\\-]+))?`);
  const close = escapeRegExp(MARKERS[style].open("@@")).replace("@@", END);
  return new RegExp(`^[ \\t]*${open}[ \\t]*$[\\s\\S]*?^[ \\t]*${close}[ \\t]*$`, "gm");
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export interface ManagedRegion {
  /** Payload version recorded in the opening marker, or null on a pre-versioned region. */
  version: string | null;
  start: number;
  end: number;
}

/** Every Myrqen-managed region in this text. More than one is a conflict. */
export function findManagedRegions(text: string, style: MarkerStyle): ManagedRegion[] {
  const found: ManagedRegion[] = [];
  const pattern = regionPattern(style);
  for (const match of text.matchAll(pattern)) {
    if (match.index === undefined) continue;
    found.push({ version: match[1] ?? null, start: match.index, end: match.index + match[0].length });
  }
  return found;
}

export interface MergeResult {
  contents: string;
  /** `create` when the file was empty or absent, `merge` when other content is kept. */
  action: "create" | "update" | "merge" | "unchanged" | "conflicted";
  preservesExistingContent: boolean;
}

/**
 * Put `body` into `existing` as the one Myrqen-managed region.
 *
 * Line endings are preserved: a file that uses CRLF keeps CRLF, because
 * rewriting every line of a user's file is exactly the kind of silent damage
 * this module exists to prevent, and on Windows it turns one small edit into a
 * whole-file diff.
 */
export function mergeManagedRegion(existing: string | null, body: string, style: MarkerStyle): MergeResult {
  const block = `${startMarker(style)}\n${body.trim()}\n${endMarker(style)}`;

  if (existing === null || existing.trim().length === 0) {
    return { contents: `${block}\n`, action: "create", preservesExistingContent: false };
  }

  const crlf = /\r\n/.test(existing);
  const normalized = existing.replace(/\r\n/g, "\n");
  const regions = findManagedRegions(normalized, style);

  if (regions.length > 1) {
    return { contents: existing, action: "conflicted", preservesExistingContent: true };
  }

  let next: string;
  if (regions.length === 1) {
    const region = regions[0]!;
    if (normalized.slice(region.start, region.end) === block) {
      return { contents: existing, action: "unchanged", preservesExistingContent: true };
    }
    next = normalized.slice(0, region.start) + block + normalized.slice(region.end);
  } else {
    // Appended, never prepended: the top of a user's instruction file is the
    // part they wrote first and read most.
    next = `${normalized.replace(/\s*$/, "")}\n\n${block}\n`;
  }

  return {
    contents: crlf ? next.replace(/\n/g, "\r\n") : next,
    action: regions.length === 1 ? "update" : "merge",
    preservesExistingContent: true
  };
}

/** Remove Myrqen's region, leaving everything else exactly as it was. */
export function removeManagedRegion(existing: string, style: MarkerStyle): { contents: string; removed: boolean; empty: boolean } {
  const crlf = /\r\n/.test(existing);
  const normalized = existing.replace(/\r\n/g, "\n");
  const regions = findManagedRegions(normalized, style);
  if (regions.length === 0) return { contents: existing, removed: false, empty: normalized.trim().length === 0 };

  // Only the seam is tidied. An earlier version normalised the whole document —
  // collapsing every run of blank lines and stripping leading whitespace — which
  // rewrote content nowhere near the region: blank lines inside fenced code
  // blocks, the indentation of a first line, the blank lines inside a YAML block
  // scalar (which are part of the string's value), and a leading byte-order
  // mark. The tool said "kept exactly as it is" while doing it.
  let next = normalized;
  for (const region of [...regions].reverse()) {
    let start = region.start;
    let end = region.end;
    // Take the newline that ended the line before the region, and the one that
    // ends the region's own last line, so the cut leaves no blank gap and no
    // joined lines. Nothing beyond those two characters is touched.
    if (next.slice(end, end + 1) === "\n") end += 1;
    if (start > 0 && next.slice(start - 1, start) === "\n") start -= 1;
    next = next.slice(0, start) + next.slice(end);
  }
  const empty = next.trim().length === 0;
  return { contents: crlf ? next.replace(/\n/g, "\r\n") : next, removed: true, empty };
}

/**
 * Write a file the way a configuration tool should: to a temporary file beside
 * the target, then renamed over it.
 *
 * A rename within a directory is atomic on every platform Myrqen supports, so a
 * process killed mid-write leaves either the old file or the new one and never
 * a truncated `CLAUDE.md`.
 *
 * A symlinked target is followed first. `AGENTS.md -> ../shared/INSTRUCTIONS.md`
 * is how a team keeps one source of truth across repositories, and renaming over
 * the link replaces it with a private copy: the shared file silently stops
 * reaching this project, and no diff shows why. Writing through the link keeps
 * the arrangement the user built.
 */
export async function writeAtomic(target: string, contents: string): Promise<void> {
  const resolved = await resolveSymlink(target);
  const directory = path.dirname(resolved);
  await fs.mkdir(directory, { recursive: true });

  let mode: number | undefined;
  try {
    mode = (await fs.stat(resolved)).mode & 0o777;
  } catch {
    mode = undefined;
  }

  const temporary = path.join(directory, `.${path.basename(resolved)}.myrqen-${process.pid}-${Date.now()}`);
  try {
    await fs.writeFile(temporary, contents, { encoding: "utf8", mode: mode ?? 0o644 });
    await fs.rename(temporary, resolved);
  } catch (error) {
    await fs.rm(temporary, { force: true });
    throw error;
  }
}

/** The file a path ultimately names, so a write goes through a link and not over it. */
async function resolveSymlink(target: string): Promise<string> {
  try {
    const stat = await fs.lstat(target);
    if (!stat.isSymbolicLink()) return target;
    return await fs.realpath(target);
  } catch {
    return target;
  }
}

/**
 * Can this file be edited without destroying bytes?
 *
 * Everything here reads a whole file as UTF-8 and writes the whole file back.
 * A file that is not valid UTF-8 — an older repository's Latin-1 instructions,
 * a Shift-JIS `CLAUDE.md`, an accidental binary byte — decodes to U+FFFD, and
 * the replacement character is what lands on disk. The original bytes are then
 * unrecoverable, and the snapshot rollback took cannot bring them back either
 * because it was taken the same way. So the answer is to decline the file and
 * say why, not to edit it and hope.
 */
export async function readsBackUnchanged(target: string): Promise<boolean> {
  let bytes: Buffer;
  try {
    bytes = await fs.readFile(target);
  } catch (error) {
    // A file that is not there yet will be created, and creation cannot corrupt
    // anything that does not exist.
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return true;
    return false;
  }
  return Buffer.compare(bytes, Buffer.from(bytes.toString("utf8"), "utf8")) === 0;
}

export async function readIfPresent(target: string): Promise<string | null> {
  try {
    return await fs.readFile(target, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  }
}

export async function pathExists(target: string): Promise<boolean> {
  try {
    await fs.access(target);
    return true;
  } catch {
    return false;
  }
}

/** True when the path exists and is a directory, following no symlink out of scope. */
export async function directoryExists(target: string): Promise<boolean> {
  try {
    const stat = await fs.lstat(target);
    if (stat.isSymbolicLink()) {
      const resolved = await fs.stat(target).catch(() => null);
      return Boolean(resolved?.isDirectory());
    }
    return stat.isDirectory();
  } catch {
    return false;
  }
}

/**
 * Could Myrqen write this path?
 *
 * When the file exists, the question is about the file. When it does not, the
 * question is about the nearest ancestor that does exist — a plan routinely
 * creates several directories at once (`.claude/skills/myrqen/references/`), and
 * asking whether a directory that has not been made yet is writable answers
 * "no" for every one of them.
 */
export async function isWritable(target: string): Promise<boolean> {
  const { constants } = await import("node:fs");
  if (await pathExists(target)) {
    try {
      await fs.access(target, constants.W_OK);
      return true;
    } catch {
      return false;
    }
  }

  let directory = path.dirname(path.resolve(target));
  for (let depth = 0; depth < 40; depth += 1) {
    if (await pathExists(directory)) {
      try {
        await fs.access(directory, constants.W_OK);
        return true;
      } catch {
        return false;
      }
    }
    const parent = path.dirname(directory);
    if (parent === directory) return false;
    directory = parent;
  }
  return false;
}

/**
 * A path a human can read without leaking where their home directory is or what
 * their username is. Every path Myrqen prints goes through this.
 */
export function displayPath(target: string, repoRoot: string, home = os.homedir()): string {
  const normalized = path.resolve(target);
  const relativeToRepo = path.relative(repoRoot, normalized);
  if (relativeToRepo && !relativeToRepo.startsWith("..") && !path.isAbsolute(relativeToRepo)) {
    return relativeToRepo.split(path.sep).join("/");
  }
  const relativeToHome = path.relative(home, normalized);
  if (relativeToHome && !relativeToHome.startsWith("..") && !path.isAbsolute(relativeToHome)) {
    return `~/${relativeToHome.split(path.sep).join("/")}`;
  }
  return normalized;
}

/** The marker Myrqen writes into a whole file it owns outright. */
export function ownedFileHeader(style: MarkerStyle): string {
  return `${startMarker(style)}\n${MARKERS[style].open(
    `Written by ${BRAND.displayName}. Edit at your own risk: "${BRAND.cliName} link" rewrites this region.`
  )}`;
}
