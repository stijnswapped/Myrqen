import ts from "typescript";
import path from "node:path";
import { calleeName, calleeTail, collect, literalTextOf } from "./helpers.js";
import { lineOf, type ParsedFile } from "./parse.js";
import { entryPointsOf } from "./entrypoints.js";
import type { RouteHint } from "../rules/context.js";

const HTTP_METHODS = new Set(["get", "post", "put", "patch", "delete", "options", "head", "all", "use"]);
/**
 * Receivers that are definitely a router. Kept only to rank candidates: a file that
 * names its router after its domain (`attachments.get(...)`, `embed.use(...)`) is
 * ordinary, and requiring one of these names made every route in such a file
 * invisible. Any identifier receiver is now accepted when the call otherwise looks
 * like a route registration.
 */
const FRAMEWORK_RECEIVERS = /^(app|router|server|api|fastify|route|r|instance)$/;

/** Receivers that are definitely NOT a router, however the call is shaped. */
const NOT_A_ROUTER = /^(res|reply|response|ctx|context|c|req|request|console|logger|log|db|database|pool|client|store|cache|redis|fs|path|crypto|JSON|Object|Array|Math|process|window|document|localStorage|headers|cookies|params|query|url|map|set|list|items|rows)$/i;

/**
 * Route discovery from the AST rather than from text.
 *
 * Three shapes are recognised, because real projects use all of them and a
 * scanner that only understands `app.get(...)` is blind to hand-rolled dispatch
 * and to file-based routing:
 *
 *  1. Framework registration:  app.get("/orders/:id", handler)
 *  2. Hand-rolled dispatch:    if (route === "GET /api/orders") { ... }
 *  3. File-based routing:      app/api/orders/[id]/route.ts exporting GET
 */
export function discoverRoutes(file: ParsedFile): RouteHint[] {
  const hints: RouteHint[] = [];

  // Framework adapters first. They recognise entry points this file's own
  // heuristics cannot see at all — a NestJS controller decorator, a SvelteKit
  // `+server.ts`, a Lambda handler, an Electron IPC channel — and they know the
  // handler node exactly, which makes attribution certain rather than nearest-above.
  for (const entry of entryPointsOf(file)) {
    hints.push({
      method: entry.method,
      path: entry.path,
      line: entry.line,
      ...(entry.node ? { node: entry.node } : {})
    });
  }

  for (const call of collect(file.source, ts.isCallExpression)) {
    const tail = calleeTail(call).toLowerCase();
    if (!HTTP_METHODS.has(tail)) continue;

    const receiver = ts.isPropertyAccessExpression(call.expression)
      ? call.expression.expression.getText(file.source)
      : "";
    if (!receiver || receiver.includes("(")) continue;
    const receiverTail = receiver.split(".").pop() ?? receiver;
    if (NOT_A_ROUTER.test(receiverTail)) continue;

    const first = call.arguments[0];
    if (!first) continue;
    const literal = literalTextOf(first);
    if (!literal || !literal.startsWith("/")) continue;

    // A registration passes a handler. Without one this is a call that merely takes
    // a path-shaped string — a cookie options object, a fetch, a file read.
    const looksLikeRegistration =
      call.arguments.length > 1 &&
      call.arguments.slice(1).some(
        (argument) =>
          ts.isArrowFunction(argument) ||
          ts.isFunctionExpression(argument) ||
          ts.isIdentifier(argument) ||
          ts.isObjectLiteralExpression(argument) ||
          ts.isArrayLiteralExpression(argument) ||
          ts.isPropertyAccessExpression(argument) ||
          ts.isCallExpression(argument)
      );
    if (!looksLikeRegistration && !FRAMEWORK_RECEIVERS.test(receiverTail)) continue;

    const handler = call.arguments.find(
      (argument) => ts.isArrowFunction(argument) || ts.isFunctionExpression(argument) || ts.isIdentifier(argument)
    );

    hints.push({
      method: tail === "use" || tail === "all" ? "ANY" : tail.toUpperCase(),
      path: normalizePath(joinPrefix(prefixFor(file, receiverTail), literal)),
      line: lineOf(file, call),
      ...(handler && !ts.isIdentifier(handler) ? { node: handler } : {})
    });
  }

  // Hand-rolled dispatch: a comparison against a "METHOD /path" or "/path"
  // literal. This is what a scanner keyed to framework calls misses entirely.
  for (const comparison of collect(file.source, ts.isBinaryExpression)) {
    if (
      comparison.operatorToken.kind !== ts.SyntaxKind.EqualsEqualsEqualsToken &&
      comparison.operatorToken.kind !== ts.SyntaxKind.EqualsEqualsToken
    ) {
      continue;
    }
    for (const side of [comparison.left, comparison.right]) {
      const literal = literalTextOf(side);
      if (!literal) continue;
      const match = /^(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+(\/\S*)$/.exec(literal);
      if (match) {
        hints.push({
          method: match[1]!,
          path: match[2]!,
          line: lineOf(file, comparison),
          ...(enclosingConsequent(comparison) ? { node: enclosingConsequent(comparison)! } : {})
        });
        continue;
      }
      if (literal.startsWith("/") && literal.length > 1 && /pathname|route|url/i.test(comparison.getText(file.source))) {
        hints.push({
          method: "ANY",
          path: literal,
          line: lineOf(file, comparison),
          ...(enclosingConsequent(comparison) ? { node: enclosingConsequent(comparison)! } : {})
        });
      }
    }
  }

  // Regex-tested dispatch: `if (method === "GET" && /^\/api\/orders\/\d+$/.test(url.pathname))`.
  // Without this the route is invisible and every finding inside the branch is
  // attributed to whichever string-literal route happened to appear above it.
  for (const call of collect(file.source, ts.isCallExpression)) {
    if (calleeTail(call) !== "test") continue;
    if (!ts.isPropertyAccessExpression(call.expression)) continue;
    const receiver = call.expression.expression;
    const pattern = regexSourceOf(receiver, file);
    if (!pattern) continue;
    const subject = call.arguments[0]?.getText(file.source) ?? "";
    if (!/pathname|\burl\b|\bpath\b|\broute\b|\bhref\b/i.test(subject)) continue;

    const routePath = pathFromPattern(pattern);
    if (!routePath) continue;

    hints.push({
      method: methodNear(call, file),
      path: routePath,
      line: lineOf(file, call),
      ...(enclosingConsequent(call) ? { node: enclosingConsequent(call)! } : {})
    });
  }

  // GraphQL resolvers reach the network through one transport route. No resolver
  // file declares a path, so without this every resolver finding is unattributed —
  // and a reader cannot act on a finding that names no endpoint.
  if (hints.length === 0 && declaresGraphqlResolvers(file)) {
    for (const group of resolverGroups(file)) {
      hints.push({ method: "POST", path: "/graphql", line: group.line, node: group.node });
    }
  }

  // tRPC procedures are addressed by name rather than by path.
  if (hints.length === 0) hints.push(...trpcProcedures(file));

  // File-based routing: the path comes from the file's own location.
  const fileRoute = routeFromFilePath(file.relativePath);
  if (fileRoute) {
    for (const statement of file.source.statements) {
      if (!ts.isFunctionDeclaration(statement) || !statement.name) continue;
      const name = statement.name.text.toUpperCase();
      if (!["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"].includes(name)) continue;
      const isExported = statement.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword);
      if (!isExported) continue;
      hints.push({ method: name, path: fileRoute, line: lineOf(file, statement), node: statement });
    }
  }

  return dedupeHints(hints).sort((a, b) => a.line - b.line);
}

/**
 * The same endpoint found twice is one endpoint.
 *
 * A framework adapter and the generic call-shape discovery legitimately overlap —
 * an itty-router registration inside a Worker looks like an Express registration —
 * and two hints for one line would make `routeCount` overstate the attack surface
 * that was actually mapped.
 */
function dedupeHints(hints: RouteHint[]): RouteHint[] {
  const seen = new Map<string, RouteHint>();
  for (const hint of hints) {
    const key = `${hint.method} ${hint.path} @${hint.line}`;
    const existing = seen.get(key);
    // Keep whichever of the two knows its handler body.
    if (!existing || (!existing.node && hint.node)) seen.set(key, hint);
  }
  return [...seen.values()];
}

/** `app/api/orders/[id]/route.ts` becomes `/api/orders/:id`. */
export function routeFromFilePath(relativePath: string): string | null {
  const normalized = relativePath.split(path.sep).join("/");
  /*
   * `app/` and `pages/` are Next.js. `api/` is the same convention under a different
   * root, which is what Medusa uses — `src/api/admin/vendors/[id]/route.ts` is
   * `/admin/vendors/:id`, spelled exactly as Next spells it, including the bracketed
   * parameter. Run 7 reported findings in those files against no endpoint at all, so
   * every rule that asks "which route is this and does it authenticate" was silent on the
   * whole surface.
   *
   * The `api/` segment is kept in the URL for Next (`app/api/thumbnail` is
   * `/api/thumbnail`) and dropped when it *is* the root, because a Medusa route file at
   * `src/api/admin/x/route.ts` answers `/admin/x`. That is decided by which alternative
   * matched rather than by guessing from the depth.
   */
  const match =
    /(?:^|\/)(?:app|pages)\/(.+)\/(route|page)\.[cm]?[jt]sx?$/.exec(normalized) ??
    /(?:^|\/)api\/(.+)\/(route)\.[cm]?[jt]sx?$/.exec(normalized);
  if (!match) return null;
  const segments = match[1]!
    .split("/")
    // Route groups such as (marketing) do not appear in the URL.
    .filter((segment) => !(segment.startsWith("(") && segment.endsWith(")")))
    .map((segment) => {
      if (segment.startsWith("[[...") && segment.endsWith("]]")) return "*";
      if (segment.startsWith("[...") && segment.endsWith("]")) return "*";
      if (segment.startsWith("[") && segment.endsWith("]")) return `:${segment.slice(1, -1)}`;
      return segment;
    });
  return `/${segments.join("/")}`;
}

function enclosingConsequent(node: ts.Node): ts.Node | undefined {
  let current: ts.Node | undefined = node.parent;
  while (current) {
    if (ts.isIfStatement(current)) return current.thenStatement;
    current = current.parent;
  }
  return undefined;
}

export function routeCount(hints: RouteHint[]): number {
  return new Set(hints.map((hint) => `${hint.method} ${hint.path}`)).size;
}

/** The source of a regular expression, whether written inline or bound to a name. */
function regexSourceOf(node: ts.Node, file: ParsedFile): string | null {
  if (ts.isRegularExpressionLiteral(node)) {
    const text = node.getText(file.source);
    const end = text.lastIndexOf("/");
    return end > 0 ? text.slice(1, end) : null;
  }
  if (ts.isNewExpression(node) && node.expression.getText(file.source) === "RegExp") {
    const first = node.arguments?.[0];
    return first && ts.isStringLiteralLike(first) ? first.text : null;
  }
  if (ts.isIdentifier(node)) {
    // A pattern held in a constant is the same route; resolve it in this file.
    for (const declaration of collect(file.source, ts.isVariableDeclaration)) {
      if (!ts.isIdentifier(declaration.name) || declaration.name.text !== node.text) continue;
      if (!declaration.initializer) continue;
      return regexSourceOf(declaration.initializer, file);
    }
  }
  return null;
}

/** Regex metacharacters that mean a segment is a parameter, not a literal. */
const DYNAMIC_SEGMENT = /[\\[\](){}+*?|]|\\d|\\w|\\S|\.\+|\.\*/;

/**
 * `^\/api\/orders\/\d+$` becomes `/api/orders/:id`. The readable form is what
 * a reader recognises and what the benchmark's ground truth records, so a
 * scanner that reports the raw pattern cannot be matched against either.
 */
function pathFromPattern(pattern: string): string | null {
  let body = pattern.replace(/^\^/, "").replace(/\$$/, "");
  // Unescape the separators so the shape is a path again.
  body = body.replace(/\\\//g, "/");
  if (!body.startsWith("/")) return null;

  const segments = body
    .slice(1)
    .split("/")
    .filter((segment) => segment.length > 0)
    .map((segment) => {
      const named = /^\(\?<([A-Za-z_][A-Za-z0-9_]*)>.*\)[?+*]?$/.exec(segment);
      if (named) return `:${named[1]}`;
      if (DYNAMIC_SEGMENT.test(segment)) return ":id";
      return segment;
    });

  if (segments.length === 0) return "/";
  return `/${segments.join("/")}`;
}

/**
 * The HTTP method compared alongside the pattern. A regex branch that also tests
 * `request.method === "GET"` is a GET route; without one the method is unknown.
 */
function methodNear(call: ts.Node, file: ParsedFile): string {
  let current: ts.Node | undefined = call.parent;
  let depth = 0;
  while (current && depth < 8) {
    if (ts.isIfStatement(current) || ts.isBinaryExpression(current)) {
      const text = current.getText(file.source);
      const match = /\b(?:method|verb)\b[^\n]{0,40}?["'`](GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)["'`]/i.exec(text);
      if (match) return match[1]!.toUpperCase();
    }
    current = current.parent;
    depth += 1;
  }
  return "ANY";
}

/** `new Router({ prefix: "/notifications" })` declared in this file. */
function prefixFor(file: ParsedFile, receiver: string): string {
  for (const declaration of collect(file.source, ts.isVariableDeclaration)) {
    if (!ts.isIdentifier(declaration.name) || declaration.name.text !== receiver) continue;
    const initializer = declaration.initializer;
    if (!initializer) return "";
    const options = ts.isNewExpression(initializer) || ts.isCallExpression(initializer) ? initializer.arguments?.[0] : undefined;
    if (!options || !ts.isObjectLiteralExpression(options)) return "";
    for (const property of options.properties) {
      if (!ts.isPropertyAssignment(property)) continue;
      if (property.name.getText(file.source).replace(/["']/g, "") !== "prefix") continue;
      return literalTextOf(property.initializer) ?? "";
    }
  }
  return "";
}

function joinPrefix(prefix: string, path: string): string {
  if (!prefix) return path;
  if (path === "/") return prefix;
  return `${prefix.replace(/\/+$/, "")}${path.startsWith("/") ? path : `/${path}`}`;
}

/**
 * A path a reader would recognise.
 *
 * A brace group means two different things depending on what precedes it, and
 * stripping both was wrong. Attached to a parameter — Express's `:filename{.+}` — it
 * is a constraint, an implementation detail of one router that matches nothing anybody
 * would write down. Standing as its own segment — Hapi's `/api/notes/{noteId}` — it
 * **is** the parameter, and removing it produced `/api/notes/`: an address that
 * matches no route, cannot be grepped for, and silently loses the fact that the
 * endpoint takes an identifier at all.
 *
 * So the constraint form is stripped and the parameter form is kept, exactly as the
 * file spells it. That is the same ruling the corpus follows: report the route as the
 * framework declares it and translate between conventions nowhere.
 */
function normalizePath(path: string): string {
  return (
    path
      // A brace group glued to the token before it is a constraint on that token.
      /*
       * A capture group rather than a lookbehind. `(?<=[^/\\s])` expressed this more
       * directly and cost **more than half the scan time of a large file** — 6.4 s
       * against 3.0 s on a 165 KB module — because V8 evaluates a lookbehind at every
       * position. Keeping the preceding character and putting it back is the same
       * assertion at a fraction of the price.
       */
      .replace(/([^/\s])\s*\{[^}]*\}/g, "$1")
      .replace(/\/{2,}/g, "/") || "/"
  );
}

/** Does this file define GraphQL resolvers? */
function declaresGraphqlResolvers(file: ParsedFile): boolean {
  const hasResolverGroup = resolverGroups(file).length > 0;
  if (!hasResolverGroup) return false;
  return /graphql|apollo|typeDefs|gql`/i.test(file.text);
}

/** Object literals holding Query, Mutation, or Subscription resolver maps. */
function resolverGroups(file: ParsedFile): Array<{ line: number; node: ts.Node }> {
  const groups: Array<{ line: number; node: ts.Node }> = [];
  for (const property of collect(file.source, ts.isPropertyAssignment)) {
    const name = property.name.getText(file.source).replace(/["']/g, "");
    if (name !== "Query" && name !== "Mutation" && name !== "Subscription") continue;
    if (!ts.isObjectLiteralExpression(property.initializer)) continue;
    groups.push({ line: lineOf(file, property), node: property.initializer });
  }
  return groups;
}

/**
 * tRPC procedures, addressed as `router.procedure`.
 *
 * A procedure has no HTTP path — that is the point of tRPC, and it is also why a
 * route-oriented analyser reports nothing useful about one. The router variable name
 * plus the procedure key is the address a developer would actually use.
 */
function trpcProcedures(file: ParsedFile): RouteHint[] {
  if (!/\b(publicProcedure|protectedProcedure|createTRPCRouter|initTRPC|t\.router|trpc)\b/.test(file.text)) return [];
  const hints: RouteHint[] = [];
  for (const declaration of collect(file.source, ts.isVariableDeclaration)) {
    if (!ts.isIdentifier(declaration.name) || !declaration.initializer) continue;
    const routerName = declaration.name.text.replace(/Router$/, "");
    const call = declaration.initializer;
    if (!ts.isCallExpression(call)) continue;
    const callee = calleeTail(call);
    if (callee !== "router" && callee !== "createTRPCRouter") continue;
    const definition = call.arguments[0];
    if (!definition || !ts.isObjectLiteralExpression(definition)) continue;
    for (const property of definition.properties) {
      if (!ts.isPropertyAssignment(property)) continue;
      const procedure = property.name.getText(file.source).replace(/["']/g, "");
      // A mutation changes state; a query does not. Stating which is what a reader
      // needs in order to judge whether a missing check matters.
      const isMutation = /\.mutation\(/.test(property.initializer.getText(file.source));
      hints.push({
        method: isMutation ? "POST" : "GET",
        path: `${routerName}.${procedure}`,
        line: lineOf(file, property),
        node: property.initializer
      });
    }
  }
  return hints;
}

void calleeName;
