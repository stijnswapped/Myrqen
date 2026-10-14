/**
 * Which exported functions hand back a value the *server* decided, not the caller.
 *
 * The mirror of `call-sites.ts`. That index answers "which parameters were observed being
 * handed caller data" — the inbound direction. This one answers the outbound question: given
 * `const { workspaceSlug } = establishOrgContext(req)`, is `workspaceSlug` something a client
 * can choose?
 *
 * Why it has to exist. The taint model treats everything reachable from `req` as
 * caller-controlled, which is right by default and wrong for the authenticated principal:
 * `req.user` is written by the authentication layer and a client cannot set it. Without this,
 * a tenant or workspace resolved from the session reads as attacker-chosen, and every
 * correctly scoped path built from it becomes a reported traversal — a confident finding on
 * code doing the right thing, which is the worst way for a rule to be wrong.
 *
 * There is already a vocabulary answer: `IDENTITY_EVIDENCE` lists about forty
 * identity-establishing call names. It works, and it stops at the edge of the list —
 * `establishOrgContext` is not on it and never will be, because the supply of names people
 * give these functions is unbounded. Run 7 measured that difference directly: recall 0.875
 * where the signal is a shape and 0.042 where it is a framework's vocabulary.
 *
 * **This index records derivation, never inference.** A function qualifies only when every
 * one of its returns is built from a server-owned property of its own parameters, from
 * constants, or from bindings that are themselves already established as such. A single
 * return that reads a header, a query parameter or an unresolvable value disqualifies the
 * whole function. The default is "the caller's", exactly as it is everywhere else.
 */
import ts from "typescript";

import { collect, walk } from "./helpers.js";
import { importsOf } from "./call-sites.js";
import type { ParsedFile } from "./parse.js";
import { CALLER_SEGMENT, ownedByServer } from "../rules/records-origin.js";

/** Local names, per importing file, that resolve to a server-owned-returning function. */
export type ServerOwnedCalls = Map<string, Set<string>>;

/** How deep a derivation chain may run before it is abandoned as unresolvable. */
const MAX_ROUNDS = 6;

function peelNode(node: ts.Node): ts.Node {
  let current = node;
  for (let depth = 0; depth < 8; depth += 1) {
    if (ts.isParenthesizedExpression(current) || ts.isAsExpression(current) || ts.isNonNullExpression(current)) {
      current = current.expression;
      continue;
    }
    if (ts.isAwaitExpression(current) || ts.isTypeAssertionExpression(current)) {
      current = current.expression;
      continue;
    }
    return current;
  }
  return current;
}

/**
 * `req.user`, `(req as any).user`, `ctx.session.actor` — a property path rooted at one of
 * this function's own parameters that passes through a segment the server owns.
 */
function readsServerProperty(node: ts.Node, parameters: ReadonlySet<string>): boolean {
  const segments: string[] = [];
  let current: ts.Node = peelNode(node);
  for (let depth = 0; depth < 8; depth += 1) {
    if (ts.isPropertyAccessExpression(current)) {
      segments.push(current.name.text);
      current = peelNode(current.expression);
      continue;
    }
    if (ts.isElementAccessExpression(current)) {
      // `req["user"]` is the same read; anything computed is not resolvable here.
      const argument = current.argumentExpression;
      if (!argument || !ts.isStringLiteral(argument)) return false;
      segments.push(argument.text);
      current = peelNode(current.expression);
      continue;
    }
    break;
  }
  if (!ts.isIdentifier(current) || !parameters.has(current.text)) return false;

  /*
   * A caller-owned container disqualifies the whole path, whatever sits inside it.
   *
   * Measured, and caught by the control test rather than by review: `req.headers["x-actor"]`
   * read as server-owned, because `ownedByServer` splits a segment on its separators and
   * `x-actor` yields `actor`, which is in the server vocabulary. The header *name* was
   * deciding provenance. A client picks header names, so this has to be checked first and
   * has to win — the cost of the alternative is an index that quietly launders caller input
   * into trusted values.
   */
  if (segments.some((segment) => CALLER_SEGMENT.has(segment.toLowerCase()))) return false;
  return segments.some((segment) => ownedByServer(segment));
}

/** Is this expression decided by the server, given what is known so far in this function? */
function serverDecided(
  node: ts.Node,
  parameters: ReadonlySet<string>,
  known: ReadonlySet<string>,
  localsFromServer: ReadonlySet<string>
): boolean {
  const inner = peelNode(node);

  if (ts.isStringLiteral(inner) || ts.isNumericLiteral(inner) || ts.isNoSubstitutionTemplateLiteral(inner)) return true;
  if (inner.kind === ts.SyntaxKind.TrueKeyword || inner.kind === ts.SyntaxKind.FalseKeyword) return true;

  if (readsServerProperty(inner, parameters)) return true;

  if (ts.isIdentifier(inner)) return localsFromServer.has(inner.text);

  // A property read off something already established as the server's stays the server's.
  if (ts.isPropertyAccessExpression(inner) || ts.isElementAccessExpression(inner)) {
    return serverDecided(inner.expression, parameters, known, localsFromServer);
  }

  if (ts.isObjectLiteralExpression(inner)) {
    return inner.properties.every((property) => {
      if (ts.isShorthandPropertyAssignment(property)) return localsFromServer.has(property.name.text);
      if (ts.isPropertyAssignment(property)) {
        return serverDecided(property.initializer, parameters, known, localsFromServer);
      }
      return false;
    });
  }

  /*
   * A call is the server's when every argument is. `tenantOf(user)` cannot invent a
   * caller-chosen value out of the session — and if it does, that is a defect in `tenantOf`,
   * reported where it is rather than here. A call with no arguments at all is not credited:
   * it could read anything, including a global holding the request.
   */
  if (ts.isCallExpression(inner)) {
    if (inner.arguments.length === 0) return false;
    return inner.arguments.every((argument) => serverDecided(argument, parameters, known, localsFromServer));
  }

  if (ts.isConditionalExpression(inner)) {
    return (
      serverDecided(inner.whenTrue, parameters, known, localsFromServer) &&
      serverDecided(inner.whenFalse, parameters, known, localsFromServer)
    );
  }

  return false;
}

/**
 * Does this function *refuse* when the principal is missing?
 *
 * The shape that separates resolving an identity from reading a field. `requireTenant` throws
 * 401 when there is no user; `establishOrgContext` throws "unauthenticated". A plain accessor
 * does not — it hands back whatever it was given.
 *
 * Required because reading a server-owned property is not by itself enough. Measured on this
 * project's own source: without it the index credited `snippetAround`, `branchTerminates` and
 * `importsFrom`, none of which resolve an identity — they read a parameter whose property
 * happens to be named like the server vocabulary (`state`, `locals`). Crediting those is a
 * *false-negative* risk, which is worse than the false positive this index exists to remove:
 * a helper returning `input.account` would launder a caller-chosen path segment into a
 * trusted one, and the traversal it enables would go unreported.
 */
function refusesWithoutPrincipal(body: ts.Block): boolean {
  let refuses = false;
  walk(body, (node) => {
    if (refuses) return;
    if (!ts.isIfStatement(node)) return;
    const stops = (branch: ts.Statement | undefined): boolean => {
      if (!branch) return false;
      if (ts.isThrowStatement(branch) || ts.isReturnStatement(branch)) return true;
      if (!ts.isBlock(branch)) return false;
      return branch.statements.some(
        (statement) => ts.isThrowStatement(statement) || ts.isReturnStatement(statement)
      );
    };
    if (stops(node.thenStatement) || stops(node.elseStatement)) refuses = true;
  });
  return refuses;
}

/** Does every return of this function hand back something the server decided? */
function returnsServerOwned(fn: ts.FunctionLikeDeclaration): boolean {
  const body = fn.body;
  if (!body || !ts.isBlock(body)) return false;
  if (!refusesWithoutPrincipal(body)) return false;

  const parameters = new Set<string>();
  for (const parameter of fn.parameters) {
    if (ts.isIdentifier(parameter.name)) parameters.add(parameter.name.text);
  }
  if (parameters.size === 0) return false;

  const returns = collect(body, ts.isReturnStatement).filter((statement) => {
    // A `return` inside a nested function belongs to that function, not this one.
    let current: ts.Node | undefined = statement.parent;
    while (current && current !== body) {
      if (ts.isFunctionLike(current)) return false;
      current = current.parent;
    }
    return true;
  });
  if (returns.length === 0) return false;

  /*
   * Grow the set of server-decided locals until it stops changing. One pass in declaration
   * order is not enough: `const id = tenantOf(user)` can be written above the `const user`
   * that feeds it in code that hoists, and reading it once would miss the chain.
   */
  const localsFromServer = new Set<string>();
  for (let round = 0; round < MAX_ROUNDS; round += 1) {
    const before = localsFromServer.size;
    walk(body, (node) => {
      if (!ts.isVariableDeclaration(node) || !node.initializer) return;
      if (!ts.isIdentifier(node.name)) return;
      if (localsFromServer.has(node.name.text)) return;
      if (serverDecided(node.initializer, parameters, parameters, localsFromServer)) {
        localsFromServer.add(node.name.text);
      }
    });
    if (localsFromServer.size === before) break;
  }

  /*
   * At least one return has to actually carry the principal out.
   *
   * Literals are credited above so that `return { id: user.id, kind: "member" }` works, but a
   * function whose returns are *only* literals has resolved nothing. Without this the index
   * credited every boolean predicate in this project's own source — `ownedByServer` returns
   * `true`/`false` and has an early return, so it matched on shape alone while deriving
   * nothing from anybody's request.
   */
  /** Does this expression carry the principal out, rather than a constant? */
  const carriesPrincipal = (node: ts.Node, depth = 0): boolean => {
    if (depth > 6) return false;
    const inner = peelNode(node);
    if (readsServerProperty(inner, parameters)) return true;
    if (ts.isIdentifier(inner)) return localsFromServer.has(inner.text);
    // `principal.workspace` — a read off a local already traced to the request.
    if (ts.isPropertyAccessExpression(inner) || ts.isElementAccessExpression(inner)) {
      return carriesPrincipal(inner.expression, depth + 1);
    }
    if (ts.isCallExpression(inner)) {
      return inner.arguments.some((argument) => carriesPrincipal(argument, depth + 1));
    }
    if (ts.isObjectLiteralExpression(inner)) {
      return inner.properties.some((property) => {
        if (ts.isShorthandPropertyAssignment(property)) return localsFromServer.has(property.name.text);
        if (ts.isPropertyAssignment(property)) return carriesPrincipal(property.initializer, depth + 1);
        return false;
      });
    }
    return false;
  };

  const derives = returns.some((statement) => Boolean(statement.expression) && carriesPrincipal(statement.expression!));
  if (!derives) return false;

  return returns.every((statement) => {
    if (!statement.expression) return false;
    return serverDecided(statement.expression, parameters, parameters, localsFromServer);
  });
}

/** Exported function declarations in a file, by the name importers see. */
function exportedFunctions(file: ParsedFile): Map<string, ts.FunctionLikeDeclaration> {
  const found = new Map<string, ts.FunctionLikeDeclaration>();
  walk(file.source, (node) => {
    const modifiers = ts.canHaveModifiers(node) ? ts.getModifiers(node) : undefined;
    const exported = modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword);
    if (!exported) return;

    if (ts.isFunctionDeclaration(node) && node.name) {
      found.set(node.name.text, node);
      return;
    }
    if (!ts.isVariableStatement(node)) return;
    for (const declaration of node.declarationList.declarations) {
      if (!ts.isIdentifier(declaration.name) || !declaration.initializer) continue;
      const initializer = peelNode(declaration.initializer);
      if (ts.isArrowFunction(initializer) || ts.isFunctionExpression(initializer)) {
        found.set(declaration.name.text, initializer);
      }
    }
  });
  return found;
}

/**
 * For every file, which of the names it imports refer to a server-owned-returning function.
 *
 * Keyed by the *importing* file, so a rule looks up a local name and never reaches across
 * files itself — the same contract `taintedParameters` keeps.
 */
export function buildServerOwnedCalls(files: readonly ParsedFile[]): ServerOwnedCalls {
  const known = new Set(files.map((file) => file.relativePath));
  const qualifying = new Map<string, Set<string>>();
  for (const file of files) {
    const names = new Set<string>();
    for (const [name, fn] of exportedFunctions(file)) {
      if (returnsServerOwned(fn)) names.add(name);
    }
    if (names.size > 0) qualifying.set(file.relativePath, names);
  }

  const byImporter: ServerOwnedCalls = new Map();
  for (const file of files) {
    const imports = importsOf(file, known);
    if (imports.size === 0) continue;
    const local = new Set<string>();
    for (const [localName, fromPath] of imports) {
      if (qualifying.get(fromPath)?.has(localName)) local.add(localName);
    }
    if (local.size > 0) byImporter.set(file.relativePath, local);
  }
  return byImporter;
}
