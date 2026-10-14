import ts from "typescript";
import type { Candidate, CandidateEvidence } from "../types.js";
import type { ParsedFile } from "../ast/parse.js";
import { endLineOf, lineOf, snippetAround } from "../ast/parse.js";
import { enclosingFunction, expressionName, functionName } from "../ast/helpers.js";
import type { TaintScope } from "../ast/taint.js";

export interface RuleContext {
  file: ParsedFile;
  /** Route strings discovered in this file, used to attribute a sink. */
  routes: RouteHint[];
  /**
   * Routes another module declared for the handlers this file exports.
   *
   * Keyed on the exported name. A handler file frequently declares no route of
   * its own — the router matching a pattern and calling it lives elsewhere — and
   * a finding with no endpoint is one a reader cannot act on without going to
   * look for the router themselves.
   */
  importedRoutes?: Map<string, RouteHint>;
  /**
   * Which of this file's exported functions were observed being handed caller data by a
   * call in another file: `exported name → parameter index → why`.
   *
   * Computed once per scan by `buildCallSiteIndex`, so a rule still only ever sees one
   * file. It records observation, never inference: a parameter appears here because some
   * real call site passed an argument this engine can already prove is caller-controlled
   * *there*. Absent when nothing in the project calls into this file.
   */
  taintedParameters?: Map<string, Map<number, string>>;
  /**
   * Names this file imports that refer to a function returning something the server decided.
   *
   * The outbound mirror of `taintedParameters`. `establishOrgContext(req)` reads the
   * workspace off `req.user`, which the authentication layer writes and a client cannot, so
   * a path built from its result is not caller-chosen even though the taint model — rightly,
   * by default — treats everything reachable from `req` as if it were.
   *
   * Computed once per scan by `buildServerOwnedCalls`, keyed by importer, so a rule looks up
   * a local name and still never reaches across files.
   */
  serverOwnedCalls?: Set<string>;
  report: (candidate: Candidate) => void;
}

export interface RouteHint {
  method: string;
  path: string;
  line: number;
  /** The node whose body implements the route, when one was identified. */
  node?: ts.Node;
}

export interface Rule {
  id: string;
  category: string;
  describes: string;
  /** Runs once per parsed file. */
  run: (context: RuleContext) => void;
}

/**
 * How a reader addresses this endpoint. **The only place a route is turned into a
 * string** — seven rules used to spell this themselves and six of them spelled it
 * wrong the same way.
 *
 * The bug worth recording, because it is not the one it looks like. Every copy
 * read `method === "ANY" ? path : `${method} ${path}``, so an any-method route came
 * out as a **bare path with no verb**. In a report that reads as a GET on the root
 * rather than "any method, dispatched inside", which is simply the wrong address.
 * And anything consuming the string by splitting on a space — the benchmark scorer
 * does exactly that — gets an empty path and can match no expected route at all, so
 * a finding at the right line with the right rule was unattributable rather than
 * merely vague. `f1b9017` fixed one of the seven; this is the other six.
 *
 * Two shapes deliberately keep no verb:
 *
 *  - A **dotted procedure name** — a tRPC procedure, an Astro action, a server
 *    function — has no HTTP method, so prefixing one names an endpoint that does
 *    not exist. Anything not starting with `/` is returned as it is.
 *  - **GraphQL** is the exception to the exception: the mount is registered with
 *    `app.use` and so carries no method, but every operation reaches it by POST,
 *    and telling a reader to probe `/graphql` without the verb is half an answer.
 */
export function formatRoute(method: string, path: string): string {
  if (!path.startsWith("/")) return path;
  if (method === "ANY") return /\/graphql$/i.test(path) ? `POST ${path}` : `ANY ${path}`;
  return `${method} ${path}`;
}

/**
 * Attribute a sink to the closest route declared above it in the same file.
 * Imprecise by design: it is used to make evidence readable, never to decide
 * whether a finding exists.
 */
export function routeFor(context: RuleContext, node: ts.Node): string | undefined {
  const hint = routeHintFor(context, node);
  if (!hint) return undefined;
  return formatRoute(hint.method, hint.path);
}

/**
 * The route a sink belongs to.
 *
 * Preference order, in the order a reader would reason:
 *
 *  1. A route whose own handler body contains the node. That is certain.
 *  2. The nearest route declared above it, which is right for inline handlers.
 *  3. The nearest route declared below it, which is right for a helper defined above
 *     the registrations — a common shape, and one that previously produced no route
 *     at all.
 *
 * A mount (`app.use("/embed", …)`) is consulted last: it is a prefix, not an answer
 * to "which endpoint is this".
 */
export function routeHintFor(context: RuleContext, node: ts.Node): RouteHint | undefined {
  const line = lineOf(context.file, node);
  const endpoints = context.routes.filter((hint) => hint.method !== "ANY");
  const mounts = context.routes.filter((hint) => hint.method === "ANY");

  const containing = endpoints.find((hint) => hint.node && containsNode(hint.node, node));
  if (containing) return containing;

  // A function another endpoint handed caller data to answers on that endpoint's address —
  // unless a router named this very function, which is the more exact statement.
  const inherited = inheritedRouteFor(context, node);
  if (inherited) return importedRouteFor(context, node) ?? inherited;

  const above = (list: RouteHint[]) =>
    list.reduce<RouteHint | undefined>(
      (best, hint) => (hint.line <= line && (!best || hint.line > best.line) ? hint : best),
      undefined
    );
  const below = (list: RouteHint[]) =>
    list.reduce<RouteHint | undefined>(
      (best, hint) => (hint.line > line && (!best || hint.line < best.line) ? hint : best),
      undefined
    );

  const local = above(endpoints) ?? below(endpoints) ?? above(mounts) ?? below(mounts);
  if (local) return local;

  // Nothing in this file declares a route, so ask what another module registered
  // the enclosing exported handler under. Consulted last and only on an exact
  // name match, so a local declaration always wins and an unrecognised helper
  // still yields no route rather than a borrowed one.
  return importedRouteFor(context, node);
}

/** The route of the call sites that seeded the function holding `node`, if they agree. */
function inheritedRouteFor(context: RuleContext, node: ts.Node): RouteHint | undefined {
  const lookup = context.file.seedRouteOf;
  if (!lookup) return undefined;
  let current: ts.Node | undefined = node.parent;
  while (current) {
    if (ts.isFunctionLike(current)) {
      const hint = lookup(current);
      if (hint) return hint;
    }
    current = current.parent;
  }
  return undefined;
}

/** The route a different module declared for the exported function holding `node`. */
function importedRouteFor(context: RuleContext, node: ts.Node): RouteHint | undefined {
  if (!context.importedRoutes || context.importedRoutes.size === 0) return undefined;

  let current: ts.Node | undefined = node;
  while (current) {
    const name = exportedFunctionName(current);
    if (name) {
      const hint = context.importedRoutes.get(name);
      if (hint) return hint;
    }
    current = current.parent;
  }
  return undefined;
}

/**
 * The name this node is exported under, when it is an exported function.
 *
 * Both spellings count, because both are ordinary: `export async function
 * listStatements()` and `export const listStatements = async () => {}`.
 */
function exportedFunctionName(node: ts.Node): string | undefined {
  const isExported = (modifiers: ts.NodeArray<ts.ModifierLike> | undefined): boolean =>
    Boolean(modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword));

  if (ts.isFunctionDeclaration(node) && node.name && isExported(node.modifiers)) return node.name.text;

  if (ts.isFunctionExpression(node) || ts.isArrowFunction(node) || ts.isFunctionDeclaration(node)) {
    const declaration = node.parent;
    if (declaration && ts.isVariableDeclaration(declaration) && ts.isIdentifier(declaration.name)) {
      const statement = declaration.parent?.parent;
      if (statement && ts.isVariableStatement(statement) && isExported(statement.modifiers)) {
        return declaration.name.text;
      }
    }
  }
  return undefined;
}

function containsNode(container: ts.Node, node: ts.Node): boolean {
  return node.getStart() >= container.getStart() && node.getEnd() <= container.getEnd();
}

export function locationOf(context: RuleContext, node: ts.Node) {
  const container = functionName(enclosingFunction(node));
  return {
    file: context.file.relativePath,
    line: lineOf(context.file, node),
    endLine: endLineOf(context.file, node),
    ...(container ? { container } : {})
  };
}

export function sourceEvidence(
  context: RuleContext,
  node: ts.Node,
  description: string
): CandidateEvidence {
  return {
    kind: "source",
    description,
    snippet: snippetAround(context.file, node),
    location: `${context.file.relativePath}:${lineOf(context.file, node)}`
  };
}

export function taintEvidence(origin: string, sink: string): CandidateEvidence {
  return {
    kind: "source",
    description: /, handed to `/.test(origin)
      ? `Data flow: ${origin} reaches ${sink}, with no validating guard on the way.`
      : `Data flow: ${origin} reaches ${sink} in the same function with no validating guard between them.`
  };
}

export function describeSink(node: ts.CallExpression): string {
  return `${expressionName(node.expression)}()`;
}

export function taintScopeName(scope: TaintScope): string {
  return functionName(scope.fn) ?? "module scope";
}
