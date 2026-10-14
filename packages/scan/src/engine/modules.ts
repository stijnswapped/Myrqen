/**
 * The module graph: what a name in one file refers to in another.
 *
 * Every cross-file question the engine asks starts here. "Which function does this call
 * reach" and "which parameter does this argument land in" are both, first, "which
 * declaration does this imported name denote", and a name that fails to resolve is a flow
 * the engine silently stops following. The spellings covered are the ones real projects
 * use, all of them:
 *
 *  - ESM named, renamed, default and namespace imports, `import x = require()`;
 *  - CommonJS `require` — whole, destructured, renamed, and `require(...).member`;
 *  - `export function`, `export const`, `export default` of a declaration or an expression,
 *    `export { a as b }`, `export { a } from`, `export * from`, `export * as ns from`;
 *  - `module.exports = …`, `module.exports.name = …`, `exports.name = …`;
 *  - index files, `.js` specifiers written for `.ts` sources, and tsconfig/jsconfig `paths`
 *    with `baseUrl` and `extends`, falling back to the suffix match the earlier index used
 *    for the conventional `@/` and `~/` aliases.
 *
 * **Resolution is against the files this scan discovered, never against `node_modules`.**
 * A bare package specifier is somebody else's code and cannot be a file here, and an
 * ambiguous alias is refused rather than guessed — inventing an edge between the wrong two
 * modules is worse than having none, because it attributes a flow to a file that never
 * received the value.
 *
 * Everything is computed lazily and memoised per file, so a scan pays only for the names
 * that some call actually asks about.
 */
import fs from "node:fs/promises";
import path from "node:path";
import ts from "typescript";
import type { ParsedFile } from "../ast/parse.js";

/** A declaration a name resolves to. `node` is the function, class, object, or instance. */
export interface Definition {
  file: ParsedFile;
  /**
   * One of: a function-like node; a class declaration or expression; an object literal (a
   * namespace-like module object); a `new` expression (a singleton instance); or a source
   * file, when the name is a whole module (`import * as ns`, a CommonJS `require`).
   */
  node: ts.Node;
}

type ImportedName = { specifier: string; imported: string };

type ExportEntry =
  | { kind: "local"; name: string }
  | { kind: "node"; node: ts.Node }
  | { kind: "reexport"; specifier: string; name: string }
  | { kind: "namespace"; specifier: string };

interface FileTables {
  declarations: Map<string, ts.Node>;
  imports: Map<string, ImportedName>;
  exports: Map<string, ExportEntry>;
  stars: string[];
}

interface PathMapping {
  /** Directory the `paths` targets are relative to. */
  base: string;
  /** `null` when the config declares a `baseUrl` but no `paths`. */
  paths: Array<{ pattern: string; targets: string[] }> | null;
  baseUrl: string | null;
}

export interface ModuleGraph {
  /** Every file in the graph, by repository-relative path. */
  readonly files: ReadonlyMap<string, ParsedFile>;
  /** The repository-relative path a specifier points at from `from`, or null. */
  resolveSpecifier(from: ParsedFile, specifier: string): string | null;
  /** What an imported (or locally declared) name denotes. */
  resolveLocal(file: ParsedFile, localName: string): Definition | null;
  /** `receiver.member` where `receiver` is a local or imported binding. */
  resolveMember(file: ParsedFile, receiver: string, member: string): Definition | null;
  /** A module's export, following re-exports. */
  exportOf(file: ParsedFile, exportName: string): Definition | null;
  /** A module-level declaration of this file by name, following local aliases. */
  localDefinition(file: ParsedFile, name: string): Definition | null;
  /** A member of a resolved definition: an object property, a class method, an instance method. */
  memberOf(definition: Definition, member: string): Definition | null;
  /** The import record behind a local name, if the name was imported. */
  importOf(file: ParsedFile, localName: string): { target: ParsedFile | null; imported: string } | null;
}

const EXTENSIONS = ["ts", "tsx", "mts", "cts", "js", "jsx", "mjs", "cjs"];
const SOURCE_EXTENSION = /\.(m|c)?(j|t)sx?$/;
/** The conventional project-alias prefixes, used only when no config maps a specifier. */
const ALIAS_PREFIX = /^(@\/|~\/|#\/|src\/)/;
/** How many re-export or alias hops a resolution may take before it is abandoned. */
const MAX_DEPTH = 8;

/* ------------------------------------------------------------------ tables */

function unwrapExpression(node: ts.Node): ts.Node {
  let current = node;
  for (let depth = 0; depth < 6; depth += 1) {
    if (
      ts.isParenthesizedExpression(current) ||
      ts.isAsExpression(current) ||
      ts.isSatisfiesExpression(current) ||
      ts.isNonNullExpression(current) ||
      ts.isTypeAssertionExpression(current)
    ) {
      current = current.expression;
      continue;
    }
    return current;
  }
  return current;
}

/** `require("x")` → `"x"`, else null. */
function requireSpecifier(node: ts.Node): string | null {
  const bare = unwrapExpression(node);
  if (!ts.isCallExpression(bare)) return null;
  if (!ts.isIdentifier(bare.expression) || bare.expression.text !== "require") return null;
  const first = bare.arguments[0];
  return first && ts.isStringLiteralLike(first) ? first.text : null;
}

/** `module.exports` or `exports`, as the receiver of an assignment. */
function isModuleExports(node: ts.Node): boolean {
  if (ts.isIdentifier(node)) return node.text === "exports";
  return (
    ts.isPropertyAccessExpression(node) &&
    ts.isIdentifier(node.expression) &&
    node.expression.text === "module" &&
    node.name.text === "exports"
  );
}

function hasExportModifier(node: ts.Node): boolean {
  const modifiers = ts.canHaveModifiers(node) ? ts.getModifiers(node) : undefined;
  return Boolean(modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword));
}

function hasDefaultModifier(node: ts.Node): boolean {
  const modifiers = ts.canHaveModifiers(node) ? ts.getModifiers(node) : undefined;
  return Boolean(modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.DefaultKeyword));
}

/** An export value: a local name when it is one, the node itself otherwise. */
function exportValue(expression: ts.Node): ExportEntry {
  const bare = unwrapExpression(expression);
  if (ts.isIdentifier(bare)) return { kind: "local", name: bare.text };
  const required = requireSpecifier(bare);
  if (required) return { kind: "namespace", specifier: required };
  return { kind: "node", node: bare };
}

function buildTables(file: ParsedFile): FileTables {
  const tables: FileTables = { declarations: new Map(), imports: new Map(), exports: new Map(), stars: [] };

  const declareVariable = (declaration: ts.VariableDeclaration, exported: boolean): void => {
    if (ts.isIdentifier(declaration.name)) {
      if (declaration.initializer) {
        const required = requireSpecifier(declaration.initializer);
        if (required) {
          tables.imports.set(declaration.name.text, { specifier: required, imported: "module" });
        } else {
          const bare = unwrapExpression(declaration.initializer);
          // `const clean = require("./util").clean`
          if (ts.isPropertyAccessExpression(bare) && requireSpecifier(bare.expression)) {
            tables.imports.set(declaration.name.text, {
              specifier: requireSpecifier(bare.expression)!,
              imported: bare.name.text
            });
          } else {
            tables.declarations.set(declaration.name.text, bare);
          }
        }
      }
      if (exported) tables.exports.set(declaration.name.text, { kind: "local", name: declaration.name.text });
      return;
    }
    // `const { query, first: pick } = require("../lib/db")`
    if (ts.isObjectBindingPattern(declaration.name) && declaration.initializer) {
      const required = requireSpecifier(declaration.initializer);
      if (!required) return;
      for (const element of declaration.name.elements) {
        if (!ts.isIdentifier(element.name)) continue;
        const imported =
          element.propertyName && ts.isIdentifier(element.propertyName) ? element.propertyName.text : element.name.text;
        tables.imports.set(element.name.text, { specifier: required, imported });
      }
    }
  };

  for (const statement of file.source.statements) {
    if (ts.isImportDeclaration(statement) && ts.isStringLiteralLike(statement.moduleSpecifier)) {
      const specifier = statement.moduleSpecifier.text;
      const clause = statement.importClause;
      if (!clause || clause.isTypeOnly) continue;
      if (clause.name) tables.imports.set(clause.name.text, { specifier, imported: "default" });
      const bindings = clause.namedBindings;
      if (bindings && ts.isNamespaceImport(bindings)) {
        tables.imports.set(bindings.name.text, { specifier, imported: "*" });
      } else if (bindings && ts.isNamedImports(bindings)) {
        for (const element of bindings.elements) {
          if (element.isTypeOnly) continue;
          tables.imports.set(element.name.text, {
            specifier,
            imported: element.propertyName?.text ?? element.name.text
          });
        }
      }
      continue;
    }
    if (ts.isImportEqualsDeclaration(statement)) {
      const reference = statement.moduleReference;
      if (ts.isExternalModuleReference(reference) && ts.isStringLiteralLike(reference.expression)) {
        tables.imports.set(statement.name.text, { specifier: reference.expression.text, imported: "module" });
      }
      continue;
    }
    if (ts.isFunctionDeclaration(statement) || ts.isClassDeclaration(statement)) {
      const name = statement.name?.text;
      if (name) tables.declarations.set(name, statement);
      if (hasExportModifier(statement)) {
        if (hasDefaultModifier(statement)) tables.exports.set("default", { kind: "node", node: statement });
        else if (name) tables.exports.set(name, { kind: "local", name });
      }
      continue;
    }
    if (ts.isVariableStatement(statement)) {
      const exported = hasExportModifier(statement);
      for (const declaration of statement.declarationList.declarations) declareVariable(declaration, exported);
      continue;
    }
    if (ts.isExportAssignment(statement)) {
      // `export default expr` (or `export = expr`).
      tables.exports.set("default", exportValue(statement.expression));
      continue;
    }
    if (ts.isExportDeclaration(statement)) {
      if (statement.isTypeOnly) continue;
      const from =
        statement.moduleSpecifier && ts.isStringLiteralLike(statement.moduleSpecifier)
          ? statement.moduleSpecifier.text
          : null;
      const clause = statement.exportClause;
      if (!clause) {
        if (from) tables.stars.push(from);
        continue;
      }
      if (ts.isNamespaceExport(clause)) {
        if (from) tables.exports.set(clause.name.text, { kind: "namespace", specifier: from });
        continue;
      }
      for (const element of clause.elements) {
        if (element.isTypeOnly) continue;
        const local = element.propertyName?.text ?? element.name.text;
        tables.exports.set(
          element.name.text,
          from ? { kind: "reexport", specifier: from, name: local } : { kind: "local", name: local }
        );
      }
      continue;
    }
    if (ts.isExpressionStatement(statement) && ts.isBinaryExpression(statement.expression)) {
      const assignment = statement.expression;
      if (assignment.operatorToken.kind !== ts.SyntaxKind.EqualsToken) continue;
      const left = assignment.left;
      // `module.exports = …`
      if (isModuleExports(left) && !ts.isIdentifier(left)) {
        const value = exportValue(assignment.right);
        tables.exports.set("default", value);
        // `module.exports = { a, b: fn }` also exports each property by name.
        const bare = unwrapExpression(assignment.right);
        if (ts.isObjectLiteralExpression(bare)) {
          for (const property of bare.properties) {
            if (ts.isShorthandPropertyAssignment(property)) {
              tables.exports.set(property.name.text, { kind: "local", name: property.name.text });
            } else if (ts.isPropertyAssignment(property) && (ts.isIdentifier(property.name) || ts.isStringLiteral(property.name))) {
              tables.exports.set(property.name.text, exportValue(property.initializer));
            } else if (ts.isMethodDeclaration(property) && ts.isIdentifier(property.name)) {
              tables.exports.set(property.name.text, { kind: "node", node: property });
            }
          }
        }
        continue;
      }
      // `exports.name = …` and `module.exports.name = …`
      if (ts.isPropertyAccessExpression(left) && isModuleExports(left.expression)) {
        tables.exports.set(left.name.text, exportValue(assignment.right));
      }
    }
  }
  return tables;
}

/* ------------------------------------------------------------------ config paths */

async function readConfig(file: string, depth = 0): Promise<{ compilerOptions?: Record<string, unknown>; dir: string } | null> {
  if (depth > 4) return null;
  let text: string;
  try {
    text = await fs.readFile(file, "utf8");
  } catch {
    return null;
  }
  const parsed = ts.parseConfigFileTextToJson(file, text);
  if (parsed.error || typeof parsed.config !== "object" || parsed.config === null) return null;
  const config = parsed.config as { extends?: unknown; compilerOptions?: Record<string, unknown> };
  const dir = path.dirname(file);
  let inherited: { compilerOptions?: Record<string, unknown>; dir: string } | null = null;
  const parents = Array.isArray(config.extends) ? config.extends : config.extends ? [config.extends] : [];
  for (const parent of parents) {
    if (typeof parent !== "string" || !parent.startsWith(".")) continue;
    const target = path.resolve(dir, parent.endsWith(".json") ? parent : `${parent}.json`);
    const loaded = await readConfig(target, depth + 1);
    if (loaded) inherited = loaded;
  }
  const own = config.compilerOptions ?? {};
  const merged: Record<string, unknown> = { ...(inherited?.compilerOptions ?? {}), ...own };
  /*
   * `baseUrl` and `paths` are relative to the config that *declares* them, not to the one
   * that extends it. Recording each against its own directory is what keeps an extended
   * base config's paths pointing where they were written to point.
   */
  const declaresBase = typeof own.baseUrl === "string";
  const declaresPaths = typeof own.paths === "object" && own.paths !== null;
  const baseDir = declaresBase || declaresPaths ? dir : (inherited?.dir ?? dir);
  return { compilerOptions: merged, dir: baseDir };
}

function mappingFrom(config: { compilerOptions?: Record<string, unknown>; dir: string }, repoRoot: string): PathMapping | null {
  const options = config.compilerOptions ?? {};
  const baseUrl = typeof options.baseUrl === "string" ? path.resolve(config.dir, options.baseUrl) : null;
  const rawPaths = typeof options.paths === "object" && options.paths !== null ? (options.paths as Record<string, unknown>) : null;
  if (!baseUrl && !rawPaths) return null;
  const base = baseUrl ?? config.dir;
  const relative = (absolute: string) => path.relative(repoRoot, absolute).split(path.sep).join("/");
  const paths = rawPaths
    ? Object.entries(rawPaths).map(([pattern, targets]) => ({
        pattern,
        targets: (Array.isArray(targets) ? targets : []).filter((t): t is string => typeof t === "string").map((target) => relative(path.resolve(base, target)))
      }))
    : null;
  return { base: relative(base), paths, baseUrl: baseUrl ? relative(baseUrl) : null };
}

/* ------------------------------------------------------------------ graph */

function normalise(joined: string): string | null {
  const parts: string[] = [];
  for (const segment of joined.split("/")) {
    if (segment === "" || segment === ".") continue;
    if (segment === "..") {
      if (parts.length === 0) return null;
      parts.pop();
      continue;
    }
    parts.push(segment);
  }
  return parts.join("/");
}

function candidatesFor(stem: string): string[] {
  const withoutExtension = stem.replace(SOURCE_EXTENSION, "");
  return [
    stem,
    ...EXTENSIONS.map((extension) => `${withoutExtension}.${extension}`),
    ...EXTENSIONS.map((extension) => `${withoutExtension}/index.${extension}`)
  ];
}

export async function buildModuleGraph(repoRoot: string, parsed: readonly ParsedFile[]): Promise<ModuleGraph> {
  const files = new Map<string, ParsedFile>();
  for (const file of parsed) files.set(file.relativePath, file);

  /*
   * Path mappings, per directory that holds a config. Read up front because reading is
   * asynchronous and resolution is not; a scan has very few of these files.
   */
  const directories = new Set<string>();
  for (const relativePath of files.keys()) {
    let directory = path.posix.dirname(relativePath);
    for (let depth = 0; depth < 32; depth += 1) {
      directories.add(directory);
      if (directory === "." || directory === "") break;
      directory = path.posix.dirname(directory);
    }
  }
  const mappings = new Map<string, PathMapping | null>();
  for (const directory of directories) {
    for (const name of ["tsconfig.json", "jsconfig.json"]) {
      const absolute = path.join(repoRoot, directory === "." ? "" : directory, name);
      const config = await readConfig(absolute);
      if (!config) continue;
      mappings.set(directory, mappingFrom(config, repoRoot));
      break;
    }
  }

  const mappingFor = (relativePath: string): PathMapping | null => {
    let directory = path.posix.dirname(relativePath);
    for (let depth = 0; depth < 32; depth += 1) {
      if (mappings.has(directory)) return mappings.get(directory) ?? null;
      if (directory === "." || directory === "") return null;
      directory = path.posix.dirname(directory);
    }
    return null;
  };

  const firstKnown = (stem: string): string | null => {
    const normalised = normalise(stem);
    if (normalised === null) return null;
    for (const candidate of candidatesFor(normalised)) if (files.has(candidate)) return candidate;
    return null;
  };

  const suffixAlias = (specifier: string): string | null => {
    const tail = specifier.replace(ALIAS_PREFIX, "").replace(SOURCE_EXTENSION, "");
    if (tail.length === 0) return null;
    const wanted = EXTENSIONS.flatMap((extension) => [`${tail}.${extension}`, `${tail}/index.${extension}`]);
    const matches: string[] = [];
    for (const candidate of files.keys()) {
      if (wanted.some((suffix) => candidate === suffix || candidate.endsWith(`/${suffix}`))) matches.push(candidate);
    }
    return matches.length === 1 ? matches[0]! : null;
  };

  const specifierCache = new Map<string, string | null>();
  const resolveSpecifier = (from: ParsedFile, specifier: string): string | null => {
    const key = `${from.relativePath}\0${specifier}`;
    if (specifierCache.has(key)) return specifierCache.get(key)!;
    let resolved: string | null = null;
    if (specifier.startsWith(".")) {
      const directory = path.posix.dirname(from.relativePath);
      resolved = firstKnown(directory === "." ? specifier : `${directory}/${specifier}`);
    } else if (!specifier.startsWith("node:")) {
      const mapping = mappingFor(from.relativePath);
      for (const entry of mapping?.paths ?? []) {
        const star = entry.pattern.indexOf("*");
        let captured: string | null = null;
        if (star === -1) {
          if (specifier === entry.pattern) captured = "";
        } else {
          const prefix = entry.pattern.slice(0, star);
          const suffix = entry.pattern.slice(star + 1);
          if (specifier.startsWith(prefix) && specifier.endsWith(suffix) && specifier.length >= prefix.length + suffix.length) {
            captured = specifier.slice(prefix.length, specifier.length - suffix.length);
          }
        }
        if (captured === null) continue;
        for (const target of entry.targets) {
          resolved = firstKnown(target.replace("*", captured));
          if (resolved) break;
        }
        if (resolved) break;
      }
      if (!resolved && mapping?.baseUrl !== null && mapping?.baseUrl !== undefined) {
        resolved = firstKnown(mapping.baseUrl ? `${mapping.baseUrl}/${specifier}` : specifier);
      }
      if (!resolved && ALIAS_PREFIX.test(specifier)) resolved = suffixAlias(specifier);
    }
    specifierCache.set(key, resolved);
    return resolved;
  };

  const tableCache = new Map<string, FileTables>();
  const tablesOf = (file: ParsedFile): FileTables => {
    let tables = tableCache.get(file.relativePath);
    if (!tables) {
      tables = buildTables(file);
      tableCache.set(file.relativePath, tables);
    }
    return tables;
  };

  const targetOf = (from: ParsedFile, specifier: string): ParsedFile | null => {
    const resolved = resolveSpecifier(from, specifier);
    return resolved ? (files.get(resolved) ?? null) : null;
  };

  const definitionOfNode = (file: ParsedFile, node: ts.Node): Definition => ({ file, node: unwrapExpression(node) });

  function localDefinition(file: ParsedFile, name: string, depth = 0): Definition | null {
    if (depth > MAX_DEPTH) return null;
    const tables = tablesOf(file);
    const declared = tables.declarations.get(name);
    if (declared) {
      // `const handler = otherHandler` — a local alias.
      if (ts.isIdentifier(declared)) return localDefinition(file, declared.text, depth + 1);
      return definitionOfNode(file, declared);
    }
    if (tables.imports.has(name)) return resolveLocal(file, name, depth + 1);
    return null;
  }

  function exportOf(file: ParsedFile, exportName: string, depth = 0, seen = new Set<string>()): Definition | null {
    if (depth > MAX_DEPTH) return null;
    const key = `${file.relativePath}#${exportName}`;
    if (seen.has(key)) return null;
    seen.add(key);
    const tables = tablesOf(file);
    const entry = tables.exports.get(exportName);
    if (entry) {
      switch (entry.kind) {
        case "local":
          return localDefinition(file, entry.name, depth + 1);
        case "node":
          return definitionOfNode(file, entry.node);
        case "reexport": {
          const target = targetOf(file, entry.specifier);
          return target ? exportOf(target, entry.name, depth + 1, seen) : null;
        }
        case "namespace": {
          const target = targetOf(file, entry.specifier);
          return target ? { file: target, node: target.source } : null;
        }
      }
    }
    if (exportName === "default") return null;
    for (const star of tables.stars) {
      const target = targetOf(file, star);
      if (!target) continue;
      const found = exportOf(target, exportName, depth + 1, seen);
      if (found) return found;
    }
    return null;
  }

  function resolveLocal(file: ParsedFile, localName: string, depth = 0): Definition | null {
    if (depth > MAX_DEPTH) return null;
    const imported = tablesOf(file).imports.get(localName);
    if (!imported) return localDefinition(file, localName, depth + 1);
    const target = targetOf(file, imported.specifier);
    if (!target) return null;
    if (imported.imported === "*") return { file: target, node: target.source };
    if (imported.imported === "module") {
      // A CommonJS `require` of a whole module is its `module.exports`, whatever that is;
      // a module with only named exports is the namespace.
      return exportOf(target, "default", depth + 1) ?? { file: target, node: target.source };
    }
    const named = exportOf(target, imported.imported, depth + 1);
    if (named) return named;
    // `import { a } from "./cjs"` where the module assigned an object to module.exports.
    const fallback = exportOf(target, "default", depth + 1);
    return fallback ? memberOf(fallback, imported.imported, depth + 1) : null;
  }

  function classMember(file: ParsedFile, declaration: ts.ClassLikeDeclaration, member: string, depth: number): Definition | null {
    for (const element of declaration.members) {
      const name = element.name && (ts.isIdentifier(element.name) || ts.isStringLiteral(element.name)) ? element.name.text : null;
      if (name !== member) continue;
      if (ts.isMethodDeclaration(element) && element.body) return { file, node: element };
      if (ts.isPropertyDeclaration(element) && element.initializer) {
        const value = unwrapExpression(element.initializer);
        if (ts.isArrowFunction(value) || ts.isFunctionExpression(value)) return { file, node: value };
      }
    }
    // One level of `extends`, because a base service is the common shape.
    const heritage = declaration.heritageClauses?.find((clause) => clause.token === ts.SyntaxKind.ExtendsKeyword);
    const base = heritage?.types[0]?.expression;
    if (base && ts.isIdentifier(base) && depth < MAX_DEPTH) {
      const resolved = localDefinition(file, base.text, depth + 1);
      if (resolved && (ts.isClassDeclaration(resolved.node) || ts.isClassExpression(resolved.node))) {
        return classMember(resolved.file, resolved.node, member, depth + 1);
      }
    }
    return null;
  }

  function memberOf(definition: Definition, member: string, depth = 0): Definition | null {
    if (depth > MAX_DEPTH) return null;
    const { file, node } = definition;
    if (ts.isSourceFile(node)) {
      return exportOf(file, member, depth + 1) ?? (() => {
        const fallback = exportOf(file, "default", depth + 1);
        return fallback && !ts.isSourceFile(fallback.node) ? memberOf(fallback, member, depth + 1) : null;
      })();
    }
    if (ts.isObjectLiteralExpression(node)) {
      for (const property of node.properties) {
        const name = property.name && (ts.isIdentifier(property.name) || ts.isStringLiteral(property.name)) ? property.name.text : null;
        if (name !== member) continue;
        if (ts.isMethodDeclaration(property)) return { file, node: property };
        if (ts.isShorthandPropertyAssignment(property)) return localDefinition(file, name, depth + 1);
        if (ts.isPropertyAssignment(property)) {
          const value = unwrapExpression(property.initializer);
          if (ts.isIdentifier(value)) return localDefinition(file, value.text, depth + 1);
          return { file, node: value };
        }
      }
      return null;
    }
    if (ts.isClassDeclaration(node) || ts.isClassExpression(node)) return classMember(file, node, member, depth + 1);
    if (ts.isNewExpression(node)) {
      const constructed = unwrapExpression(node.expression);
      if (!ts.isIdentifier(constructed)) return null;
      const resolved = localDefinition(file, constructed.text, depth + 1);
      if (!resolved) return null;
      if (ts.isClassDeclaration(resolved.node) || ts.isClassExpression(resolved.node)) {
        return classMember(resolved.file, resolved.node, member, depth + 1);
      }
      return null;
    }
    return null;
  }

  function resolveMember(file: ParsedFile, receiver: string, member: string): Definition | null {
    const base = resolveLocal(file, receiver);
    return base ? memberOf(base, member) : null;
  }

  function importOf(file: ParsedFile, localName: string): { target: ParsedFile | null; imported: string } | null {
    const imported = tablesOf(file).imports.get(localName);
    if (!imported) return null;
    return { target: targetOf(file, imported.specifier), imported: imported.imported };
  }

  return {
    files,
    resolveSpecifier,
    resolveLocal: (file, localName) => resolveLocal(file, localName),
    resolveMember,
    exportOf: (file, exportName) => exportOf(file, exportName),
    localDefinition: (file, name) => localDefinition(file, name),
    memberOf: (definition, member) => memberOf(definition, member),
    importOf
  };
}
