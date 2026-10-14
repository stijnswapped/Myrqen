import ts from "typescript";
import path from "node:path";
import { calleeTail, collect, literalTextOf, walk } from "./helpers.js";
import type { ParsedFile } from "./parse.js";
import type { RouteHint } from "../rules/context.js";

/**
 * Routes declared in one module for a handler that lives in another.
 *
 * A handler file very often declares no route at all. The router is somewhere
 * else — `main.ts` matching a `URLPattern` and calling an imported function, an
 * Express router assembled from imported controllers, a Bun `routes` table
 * pointing at imported handlers — and the file holding the defect says nothing
 * about the address it answers on.
 *
 * That cost real findings rather than only cosmetics. A candidate with no route
 * cannot be matched against ground truth that names one, so a correct detection
 * on the correct line was scored as a miss; and a reader handed a finding with
 * no endpoint has to go and find the router themselves before they can judge it.
 *
 * The index is deliberately narrow. It records a route only when a registration
 * hands it an identifier that this file IMPORTED, and it resolves that import to
 * a path rather than matching on the name — so two handlers called `handler` in
 * different modules can never be confused for each other. Anything it cannot
 * resolve is left out, and the finding keeps no route, exactly as before.
 */

export interface ImportedRoute extends RouteHint {
  /** The module that declared this route, for the evidence. */
  declaredIn: string;
}

/** Exported handler name → the route another module registered it under. */
export type RouteIndex = Map<string, Map<string, ImportedRoute>>;

const HTTP_METHODS = new Set(["get", "post", "put", "patch", "delete", "options", "head", "all", "use"]);
const VERB_KEYS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]);

/** Receivers that are never a router, however the call is shaped. */
const NOT_A_ROUTER = /^(res|reply|response|ctx|context|c|req|request|console|logger|log|db|pool|client|store|cache|redis|fs|path|crypto|JSON|Object|Array|Math|process)$/i;

/**
 * What this file imports, as local name → resolved repository-relative path.
 *
 * Only relative specifiers are resolved: a bare package name is somebody else's
 * code and cannot be a file in this scan.
 */
function importedNames(file: ParsedFile): Map<string, string> {
  const resolved = new Map<string, string>();
  const directory = path.posix.dirname(file.relativePath);

  const record = (localName: string, specifier: string): void => {
    if (!specifier.startsWith(".")) return;
    resolved.set(localName, path.posix.normalize(path.posix.join(directory, specifier)));
  };

  for (const statement of file.source.statements) {
    if (!ts.isImportDeclaration(statement) || !ts.isStringLiteralLike(statement.moduleSpecifier)) continue;
    const specifier = statement.moduleSpecifier.text;
    const bindings = statement.importClause?.namedBindings;
    if (bindings && ts.isNamedImports(bindings)) {
      for (const element of bindings.elements) {
        // `import { listStatements as list }` — the local name is what the
        // registration uses, the property name is what the other file exports.
        record(element.name.text, specifier);
      }
    }
    if (statement.importClause?.name) record(statement.importClause.name.text, specifier);
  }
  return resolved;
}

/**
 * The exported name a local binding refers to in the module it came from.
 *
 * `import { listStatements as list }` means the other file exports
 * `listStatements`, and that is the name the index must be keyed on.
 */
function exportedNameFor(file: ParsedFile, localName: string): string {
  for (const statement of file.source.statements) {
    if (!ts.isImportDeclaration(statement)) continue;
    const bindings = statement.importClause?.namedBindings;
    if (!bindings || !ts.isNamedImports(bindings)) continue;
    for (const element of bindings.elements) {
      if (element.name.text !== localName) continue;
      return element.propertyName?.text ?? element.name.text;
    }
  }
  return localName;
}

/** `/a//b/` becomes `/a/b`. Parameter syntax is kept exactly as written. */
function normalize(route: string): string {
  return route.replace(/\/{2,}/g, "/") || "/";
}

/**
 * `^\/accounts\/([^/]+)\/statements$` and `/accounts/:accountId/statements` both
 * describe the same endpoint. A `URLPattern` keeps its own syntax, which is what
 * a developer wrote down, so it is passed through untouched.
 */
function pathFromPatternLiteral(value: string): string | null {
  if (value.startsWith("/")) return normalize(value);
  return null;
}

/**
 * The branch a node sits in — the scope a route/handler pairing may span.
 *
 * The enclosing `if` is preferred over the statement inside it, because the
 * condition is where a dispatcher names the pattern it just matched:
 * `if (statements && request.method === "GET") return listStatements(…)`. Taking
 * only the `return` sees the handler and nothing that identifies the route.
 */
function enclosingStatement(node: ts.Node): ts.Node | undefined {
  let current: ts.Node | undefined = node;
  let fallback: ts.Node | undefined;
  while (current) {
    if (ts.isIfStatement(current) || ts.isCaseClause(current)) return current;
    if (!fallback && (ts.isReturnStatement(current) || ts.isExpressionStatement(current) || ts.isVariableStatement(current))) {
      fallback = current;
    }
    if (ts.isFunctionDeclaration(current) || ts.isArrowFunction(current) || ts.isFunctionExpression(current)) break;
    current = current.parent;
  }
  return fallback;
}

/**
 * Path literals reachable from this node by following local bindings.
 *
 * Depth-limited, and only through variable declarations in the same file, so it
 * cannot wander into unrelated constants. A dispatcher that hides its paths
 * behind more indirection than this yields nothing, which leaves the handler
 * unattributed rather than attributed to a guess.
 */
function pathsBehind(node: ts.Node, file: ParsedFile, depth: number): string[] {
  if (depth <= 0) return [];
  const found: string[] = [];
  const seen = new Set<string>();
  const declarations = declarationsByName(file);

  walk(node, (inner) => {
    if (!ts.isIdentifier(inner) || seen.has(inner.text)) return;
    seen.add(inner.text);
    for (const declaration of declarations.get(inner.text) ?? []) {
      if (!declaration.initializer) continue;
      const direct = pathLiteralsIn(declaration.initializer, file);
      if (direct.length > 0) found.push(...direct);
      else found.push(...pathsBehind(declaration.initializer, file, depth - 1));
    }
  });
  return found;
}

/**
 * Every named variable declaration in the file, indexed by name, computed once.
 *
 * This was the engine's worst performance defect and it was invisible from the
 * corpus, where a case is a few kilobytes. `pathsBehind` walked the node it was
 * given and, **for every identifier it met**, collected every variable declaration
 * in the whole file and scanned the list for a name match. On a 89 KB module that is
 * ten thousand identifiers times a full-file collect: measured at **18.4 seconds for
 * one file**, against 26 ms to parse it and 1 ms to walk it once. Scanning this
 * repository's own source took 205 seconds, almost all of it here.
 *
 * The same work, done once per file and looked up by name, is a `Map`.
 */
const DECLARATION_INDEX = new WeakMap<ts.SourceFile, Map<string, ts.VariableDeclaration[]>>();

function declarationsByName(file: ParsedFile): Map<string, ts.VariableDeclaration[]> {
  const cached = DECLARATION_INDEX.get(file.source);
  if (cached) return cached;
  const index = new Map<string, ts.VariableDeclaration[]>();
  for (const declaration of collect(file.source, ts.isVariableDeclaration)) {
    if (!ts.isIdentifier(declaration.name)) continue;
    const bucket = index.get(declaration.name.text);
    if (bucket) bucket.push(declaration);
    else index.set(declaration.name.text, [declaration]);
  }
  DECLARATION_INDEX.set(file.source, index);
  return index;
}

/** Every string literal in this node that looks like a path. */
function pathLiteralsIn(node: ts.Node, file: ParsedFile): string[] {
  const paths: string[] = [];
  walk(node, (inner) => {
    const literal = literalTextOf(inner);
    if (literal && literal.startsWith("/")) paths.push(normalize(literal));
  });
  void file;
  return paths;
}

/** The HTTP verb compared to a literal anywhere inside this node. */
function methodIn(node: ts.Node, file: ParsedFile): string {
  const text = node.getText(file.source);
  const match = /\b(?:method|verb)\b[^\n]{0,60}?["'`](GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)["'`]/i.exec(text);
  return match ? match[1]!.toUpperCase() : "ANY";
}

/**
 * Read one file as a router, and record what it says about handlers elsewhere.
 */
function indexOneFile(file: ParsedFile, index: RouteIndex): void {
  const imports = importedNames(file);
  if (imports.size === 0) return;

  const remember = (localName: string, hint: RouteHint): void => {
    const target = imports.get(localName);
    if (!target) return;
    const exported = exportedNameFor(file, localName);
    const forFile = index.get(target) ?? new Map<string, ImportedRoute>();
    // A handler registered twice has no single address, and guessing one would
    // put a finding on an endpoint it may not belong to. The first registration
    // wins only when it is the only one; a second, different one erases both.
    const existing = forFile.get(exported);
    if (existing) {
      if (existing.method !== hint.method || existing.path !== hint.path) {
        forFile.set(exported, { ...existing, path: "", method: "AMBIGUOUS", declaredIn: file.relativePath });
      }
    } else {
      forFile.set(exported, { ...hint, declaredIn: file.relativePath });
    }
    index.set(target, forFile);
  };

  // 1. Framework registration handing over an imported identifier:
  //    `router.get("/invoices/:id", showInvoice)`.
  for (const call of collect(file.source, ts.isCallExpression)) {
    const tail = calleeTail(call).toLowerCase();
    if (!HTTP_METHODS.has(tail)) continue;
    const receiver = ts.isPropertyAccessExpression(call.expression)
      ? call.expression.expression.getText(file.source).split(".").pop() ?? ""
      : "";
    if (receiver && NOT_A_ROUTER.test(receiver)) continue;

    const first = call.arguments[0];
    const declared = first ? literalTextOf(first) : null;
    if (!declared || !declared.startsWith("/")) continue;

    for (const argument of call.arguments.slice(1)) {
      if (!ts.isIdentifier(argument)) continue;
      remember(argument.text, {
        method: tail === "use" || tail === "all" ? "ANY" : tail.toUpperCase(),
        path: normalize(declared),
        line: 0
      });
    }
  }

  // 2. A routes table whose values are imported handlers:
  //    `routes: { "/users/:id": { GET: listUsers } }`, and the bare-handler form.
  for (const property of collect(file.source, ts.isPropertyAssignment)) {
    const key = literalTextOf(property.name) ?? property.name.getText(file.source).replace(/["']/g, "");
    const declared = pathFromPatternLiteral(key);
    if (!declared) continue;

    if (ts.isIdentifier(property.initializer)) {
      remember(property.initializer.text, { method: "ANY", path: declared, line: 0 });
      continue;
    }
    if (!ts.isObjectLiteralExpression(property.initializer)) continue;
    for (const verb of property.initializer.properties) {
      if (!ts.isPropertyAssignment(verb) || !ts.isIdentifier(verb.initializer)) continue;
      const name = verb.name.getText(file.source).replace(/["']/g, "").toUpperCase();
      if (!VERB_KEYS.has(name)) continue;
      remember(verb.initializer.text, { method: name, path: declared, line: 0 });
    }
  }

  // 3. Pattern dispatch: a path literal and a call to an imported handler in the
  //    same branch. This is what a hand-rolled router looks like, and it is the
  //    shape a framework-keyed reader misses entirely.
  //
  //        if (statements.exec(url)) return listStatements(request, session, id);
  //
  //    The pairing is scoped to one branch, so an unrelated handler further down
  //    the dispatcher cannot borrow this path.
  for (const call of collect(file.source, ts.isCallExpression)) {
    if (!ts.isIdentifier(call.expression)) continue;
    const localName = call.expression.text;
    if (!imports.has(localName)) continue;

    const branch = enclosingStatement(call);
    if (!branch) continue;

    let paths = pathLiteralsIn(branch, file);
    // The path is normally two hops away, not one. A dispatcher matches a
    // pattern into a local — `const statements = STATEMENTS.exec(url)` — and
    // tests that local in the condition, so the branch names neither the pattern
    // constant nor the path. Following identifiers to their initialisers, and
    // then the identifiers in those, is what reaches the literal.
    if (paths.length === 0) paths = pathsBehind(branch, file, 3);
    // Exactly one candidate path, or the pairing is a guess.
    const unique = [...new Set(paths)];
    if (unique.length !== 1) continue;

    remember(localName, { method: methodIn(branch, file), path: unique[0]!, line: 0 });
  }
}

/**
 * Build the index across every file in the scan.
 *
 * Called with the files already parsed once, so this costs a walk rather than a
 * second parse of the repository.
 */
export function buildRouteIndex(files: ParsedFile[]): RouteIndex {
  const index: RouteIndex = new Map();
  for (const file of files) {
    try {
      indexOneFile(file, index);
    } catch {
      // A router this cannot read leaves its handlers unattributed, which is the
      // behaviour every file had before this existed.
    }
  }
  return index;
}

/** The routes another module declared for the handlers this file exports. */
export function routesForFile(index: RouteIndex, file: ParsedFile): Map<string, ImportedRoute> {
  const withoutExtension = file.relativePath.replace(/\.[cm]?[jt]sx?$/, "");
  for (const [target, routes] of index) {
    const targetWithout = target.replace(/\.[cm]?[jt]sx?$/, "");
    if (targetWithout === withoutExtension || targetWithout === `${withoutExtension}/index`) {
      return new Map([...routes].filter(([, route]) => route.method !== "AMBIGUOUS"));
    }
  }
  return new Map();
}
