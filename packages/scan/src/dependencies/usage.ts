import ts from "typescript";
import type { ParsedFile } from "../ast/parse.js";
import { lineOf } from "../ast/parse.js";
import { attributedRoute } from "../rules/attribution.js";
import type { RouteHint, RuleContext } from "../rules/context.js";
import { ADVISORY_SNAPSHOT } from "./advisory-snapshot.js";

/**
 * Which package exports the application's own code uses, and where.
 *
 * This is the reachability half of the dependency check (ADR 019). A vulnerable
 * version that is installed is a supply-chain fact; one whose vulnerable function is
 * called from the application is a finding. The difference is recorded here, per
 * package, as the set of exports the application touches and the first place it
 * touches each one.
 *
 * The spec is deliberately small so the engine's call graph can replace it:
 *
 *  - an import or `require` of a package binds a local name to the module, to its
 *    default, or to named exports;
 *  - a named binding that is referenced counts as using that export;
 *  - a module or default binding counts as using `default` when called or constructed,
 *    and as using `x` when `.x` is read off it — which is how `_.merge` reaches lodash's
 *    `merge` whether it was written `import _ from` or `require`;
 *  - a subpath import (`lodash/merge`) is recorded as the subpath.
 *
 * What it cannot see, and therefore never claims: a package reached through another
 * package (express's own use of `qs`), a function handed in from a module this file
 * imports, and anything behind a dynamic `require(variable)`. Those are listed as
 * present but not reached, never as safe.
 *
 * Method names (`.redirect(`) are recorded separately as a weaker signal, for
 * advisories whose vulnerable code is a method on an object the package returns.
 */
export interface Site {
  file: string;
  line: number;
  /** The route the use sits in, for packages and methods an advisory can name. */
  route?: string;
}

/**
 * Route attribution is only worth its cost where a finding can follow: a package in
 * the advisory snapshot, or a method name an advisory's curation lists.
 */
const WATCHED_PACKAGES = new Set(ADVISORY_SNAPSHOT.packages);
const CURATED_MEMBERS = new Set(ADVISORY_SNAPSHOT.advisories.flatMap((advisory) => advisory.members ?? []));

export class DependencyUsage {
  /** package → export (or `default`, or a subpath such as `lodash/merge`) → first site. */
  readonly exports = new Map<string, Map<string, Site>>();
  /** package → first import site. */
  readonly imports = new Map<string, Site>();
  /** method name → first call site, across every application file. */
  readonly memberCalls = new Map<string, Site>();

  record(file: ParsedFile, routes: RouteHint[] = []): void {
    const bindings = new Map<string, { pkg: string; kind: "module" | "named"; exported: string }>();
    const context: RuleContext = { file, routes, report: () => undefined };

    const note = (map: Map<string, Site>, key: string, node: ts.Node, attribute = false): void => {
      const site: Site = { file: file.relativePath, line: lineOf(file, node) };
      const existing = map.get(key);
      if (existing && !before(site, existing)) return;
      const route = attribute ? attributedRoute(context, node) : undefined;
      map.set(key, route ? { ...site, route } : site);
    };
    const useExport = (pkg: string, exported: string, node: ts.Node): void => {
      let map = this.exports.get(pkg);
      if (!map) {
        map = new Map();
        this.exports.set(pkg, map);
      }
      note(map, exported, node, WATCHED_PACKAGES.has(pkg));
    };
    const imported = (specifier: string, node: ts.Node): { pkg: string; subpath: string | null } | null => {
      const parsed = packageOf(specifier);
      if (!parsed) return null;
      note(this.imports, parsed.pkg, node);
      if (parsed.subpath) useExport(parsed.pkg, parsed.subpath, node);
      return parsed;
    };

    const visit = (node: ts.Node): void => {
      if (ts.isImportDeclaration(node) && ts.isStringLiteralLike(node.moduleSpecifier) && !node.importClause?.isTypeOnly) {
        const parsed = imported(node.moduleSpecifier.text, node);
        const clause = node.importClause;
        if (parsed && clause) {
          if (clause.name) bindings.set(clause.name.text, { pkg: parsed.pkg, kind: "module", exported: "default" });
          const named = clause.namedBindings;
          if (named && ts.isNamespaceImport(named)) bindings.set(named.name.text, { pkg: parsed.pkg, kind: "module", exported: "default" });
          if (named && ts.isNamedImports(named)) {
            for (const element of named.elements) {
              if (element.isTypeOnly) continue;
              const exported = (element.propertyName ?? element.name).text;
              bindings.set(element.name.text, { pkg: parsed.pkg, kind: "named", exported });
            }
          }
        }
        return;
      }

      if (ts.isCallExpression(node) && isRequireOrImport(node)) {
        const specifier = node.arguments[0];
        if (specifier && ts.isStringLiteralLike(specifier)) {
          const parsed = imported(specifier.text, node);
          if (parsed) bindRequire(node, parsed.pkg, bindings, useExport);
        }
      }

      if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
        const member = node.expression.name.text;
        note(this.memberCalls, member, node, CURATED_MEMBERS.has(member));
      }

      node.forEachChild(visit);
    };
    visit(file.source);

    if (bindings.size === 0) return;

    // Second pass: what each binding is used for.
    const walkUses = (node: ts.Node): void => {
      if (ts.isIdentifier(node) && bindings.has(node.text) && !isDeclarationName(node)) {
        const binding = bindings.get(node.text)!;
        const parent = node.parent;
        if (binding.kind === "named") {
          useExport(binding.pkg, binding.exported, node);
        } else if (parent && ts.isPropertyAccessExpression(parent) && parent.expression === node) {
          useExport(binding.pkg, parent.name.text, parent);
        } else if (parent && (ts.isCallExpression(parent) || ts.isNewExpression(parent)) && parent.expression === node) {
          useExport(binding.pkg, "default", parent);
        } else if (parent && (ts.isCallExpression(parent) || ts.isNewExpression(parent)) && parent.arguments?.includes(node as ts.Expression)) {
          // `app.use(helmet)` hands the module itself to code that will call it.
          useExport(binding.pkg, "default", parent);
        }
      }
      node.forEachChild(walkUses);
    };
    walkUses(file.source);
  }
}

function bindRequire(
  call: ts.CallExpression,
  pkg: string,
  bindings: Map<string, { pkg: string; kind: "module" | "named"; exported: string }>,
  useExport: (pkg: string, exported: string, node: ts.Node) => void
): void {
  let holder: ts.Node = call.parent;
  while (holder && (ts.isAwaitExpression(holder) || ts.isParenthesizedExpression(holder))) holder = holder.parent;
  if (ts.isVariableDeclaration(holder)) {
    if (ts.isIdentifier(holder.name)) bindings.set(holder.name.text, { pkg, kind: "module", exported: "default" });
    if (ts.isObjectBindingPattern(holder.name)) {
      for (const element of holder.name.elements) {
        if (!ts.isIdentifier(element.name)) continue;
        const exported = element.propertyName && ts.isIdentifier(element.propertyName) ? element.propertyName.text : element.name.text;
        bindings.set(element.name.text, { pkg, kind: "named", exported });
      }
    }
    return;
  }
  // require("pkg").merge(...) and require("pkg")(...)
  if (ts.isPropertyAccessExpression(holder) && holder.expression === call.parent) useExport(pkg, holder.name.text, holder);
  else if (ts.isPropertyAccessExpression(call.parent)) useExport(pkg, call.parent.name.text, call.parent);
  else if (ts.isCallExpression(call.parent) && call.parent.expression === call) useExport(pkg, "default", call.parent);
}

function isRequireOrImport(call: ts.CallExpression): boolean {
  if (call.expression.kind === ts.SyntaxKind.ImportKeyword) return true;
  return ts.isIdentifier(call.expression) && call.expression.text === "require";
}

function isDeclarationName(node: ts.Identifier): boolean {
  const parent = node.parent;
  if (!parent) return false;
  if (ts.isImportClause(parent) || ts.isImportSpecifier(parent) || ts.isNamespaceImport(parent)) return true;
  if (ts.isVariableDeclaration(parent) && parent.name === node) return true;
  if (ts.isBindingElement(parent)) return true;
  if (ts.isPropertyAccessExpression(parent) && parent.name === node) return true;
  if (ts.isPropertyAssignment(parent) && parent.name === node) return true;
  return false;
}

/**
 * `lodash` → lodash; `lodash/merge` → lodash with subpath `lodash/merge`;
 * `@scope/pkg/sub` → @scope/pkg with subpath. Relative paths, node built-ins and
 * aliases (`@/lib`, `~/x`, `#internal`) are not packages.
 */
export function packageOf(specifier: string): { pkg: string; subpath: string | null } | null {
  if (!specifier || /^(?:\.|\/|node:|#|~|@\/|bun:|deno:|https?:)/.test(specifier)) return null;
  const parts = specifier.split("/");
  if (specifier.startsWith("@")) {
    if (parts.length < 2) return null;
    const pkg = `${parts[0]}/${parts[1]}`;
    return { pkg, subpath: parts.length > 2 ? specifier : null };
  }
  if (BUILTINS.has(parts[0]!)) return null;
  return { pkg: parts[0]!, subpath: parts.length > 1 ? specifier : null };
}

const BUILTINS = new Set([
  "assert", "async_hooks", "buffer", "child_process", "cluster", "console", "constants", "crypto", "dgram", "diagnostics_channel",
  "dns", "domain", "events", "fs", "http", "http2", "https", "inspector", "module", "net", "os", "path", "perf_hooks", "process",
  "punycode", "querystring", "readline", "repl", "stream", "string_decoder", "sys", "timers", "tls", "trace_events", "tty",
  "url", "util", "v8", "vm", "wasi", "worker_threads", "zlib", "test"
]);

function before(a: Site, b: Site): boolean {
  return a.file < b.file || (a.file === b.file && a.line < b.line);
}
