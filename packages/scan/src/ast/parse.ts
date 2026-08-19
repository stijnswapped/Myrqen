import fs from "node:fs/promises";
import path from "node:path";
import ts from "typescript";

export interface ParsedFile {
  /** Repository-relative, POSIX separators, so findings are portable. */
  relativePath: string;
  absolutePath: string;
  text: string;
  source: ts.SourceFile;
  language: "TypeScript" | "JavaScript";
}

const SCRIPT_KINDS: Record<string, ts.ScriptKind> = {
  ".ts": ts.ScriptKind.TS,
  ".tsx": ts.ScriptKind.TSX,
  ".mts": ts.ScriptKind.TS,
  ".cts": ts.ScriptKind.TS,
  ".js": ts.ScriptKind.JS,
  ".jsx": ts.ScriptKind.JSX,
  ".mjs": ts.ScriptKind.JS,
  ".cjs": ts.ScriptKind.JS
};

export const PARSEABLE_EXTENSIONS = Object.keys(SCRIPT_KINDS);

const IGNORED_DIRECTORIES = new Set([
  "node_modules",
  ".git",
  ".next",
  "dist",
  "dist-tsc",
  "build",
  "out",
  "coverage",
  "vendor",
  "target",
  ".venv",
  "venv",
  "__pycache__",
  ".turbo",
  ".pnpm-store",
  ".myrqen",
  ".cache",
  ".audit",
  ".data"
]);

/**
 * Files whose vulnerabilities are not the application's. Reported separately as
 * a coverage note rather than silently dropped, because "we skipped your tests"
 * is information the reader needs.
 */
const NON_APPLICATION = /(^|\/)(tests?|__tests__|__mocks__|e2e|spec|fixtures?|examples?|benchmark)(\/|$)|\.(test|spec)\.[cm]?[jt]sx?$/;

export interface DiscoveredFiles {
  files: string[];
  skipped: string[];
  bytes: number;
}

export async function discoverSourceFiles(
  repoRoot: string,
  options: { maxFiles: number; maxFileBytes: number }
): Promise<DiscoveredFiles> {
  const files: string[] = [];
  const skipped: string[] = [];
  let bytes = 0;

  async function visit(directory: string): Promise<void> {
    if (files.length >= options.maxFiles) return;
    let entries;
    try {
      entries = await fs.readdir(directory, { withFileTypes: true, encoding: "utf8" });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (files.length >= options.maxFiles) return;
      const full = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) {
        // A symlink can point outside the repository or into a cycle. Neither is
        // worth following for an analysis scoped to the project's own source.
        skipped.push(full);
        continue;
      }
      if (entry.isDirectory()) {
        if (IGNORED_DIRECTORIES.has(entry.name) || (entry.name.startsWith(".") && entry.name !== ".github")) continue;
        await visit(full);
        continue;
      }
      if (!entry.isFile()) continue;
      if (!PARSEABLE_EXTENSIONS.includes(path.extname(entry.name))) continue;
      let size = 0;
      try {
        size = (await fs.stat(full)).size;
      } catch {
        continue;
      }
      if (size > options.maxFileBytes) {
        skipped.push(full);
        continue;
      }
      bytes += size;
      files.push(full);
    }
  }

  await visit(repoRoot);
  return { files: files.sort(), skipped, bytes };
}

export function isNonApplicationFile(relativePath: string): boolean {
  return NON_APPLICATION.test(relativePath);
}

export async function parseFile(repoRoot: string, absolutePath: string): Promise<ParsedFile | { error: string }> {
  let text: string;
  try {
    text = await fs.readFile(absolutePath, "utf8");
  } catch (error) {
    return { error: error instanceof Error ? error.message : "unreadable" };
  }

  const extension = path.extname(absolutePath);
  const scriptKind = SCRIPT_KINDS[extension] ?? ts.ScriptKind.TS;
  const relativePath = path.relative(repoRoot, absolutePath).split(path.sep).join("/");

  try {
    const source = ts.createSourceFile(relativePath, text, ts.ScriptTarget.Latest, true, scriptKind);
    return {
      relativePath,
      absolutePath,
      text,
      source,
      language: scriptKind === ts.ScriptKind.JS || scriptKind === ts.ScriptKind.JSX ? "JavaScript" : "TypeScript"
    };
  } catch (error) {
    return { error: error instanceof Error ? error.message : "parse failed" };
  }
}

export function lineOf(file: ParsedFile, node: ts.Node): number {
  return file.source.getLineAndCharacterOfPosition(node.getStart(file.source)).line + 1;
}

export function endLineOf(file: ParsedFile, node: ts.Node): number {
  return file.source.getLineAndCharacterOfPosition(node.getEnd()).line + 1;
}

/**
 * A few lines around the node. Comments are included because a reviewer reading
 * evidence needs the context, but rules never *match* on comments: the parser
 * gives them no AST presence, which is what makes this engine immune to the
 * "scary string in a comment" false positive.
 */
export function snippetAround(file: ParsedFile, node: ts.Node, context = 2): string {
  const lines = file.text.split("\n");
  const start = Math.max(0, lineOf(file, node) - 1 - context);
  const end = Math.min(lines.length, endLineOf(file, node) + context);
  return lines.slice(start, end).join("\n").slice(0, 1200);
}
