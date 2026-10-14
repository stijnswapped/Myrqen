import ts from "typescript";
import { calleeTail, collect, enclosingFunction, functionName, literalTextOf, walk } from "../ast/helpers.js";
import { routeFromFilePath } from "../ast/routes.js";
import { formatRoute, routeHintFor, type RuleContext } from "./context.js";

/* ------------------------------------------------------------------ *
 * Route attribution
 *
 * `discoverRoutes` understands framework registration, `"METHOD /path"`
 * comparisons, regex `.test` dispatch, and file-based route handlers. Three
 * shapes it does not model appear in almost every hand-rolled Node server, and
 * a finding in one of them carries no route at all — which is the first thing a
 * reader needs in order to probe it:
 *
 *   1. A table of route objects: `[{ method: "GET", pattern: /^\/x$/, handler: f }]`
 *   2. A table keyed by the pair: `new Map([["POST /x", f]])`
 *   3. An `if` chain testing the method and the path, calling a named handler
 *
 * It also formats the result the way a reader addresses the endpoint: a tRPC
 * procedure has no HTTP verb, a `/graphql` mount is reached by POST, and an
 * App Router `page.tsx` is a GET of its own path.
 *
 * All of this belongs upstream in `ast/routes.ts` — this is the third
 * independent copy in the rule set, alongside the ones in `parsing.ts` and
 * `records.ts`.
 * ------------------------------------------------------------------ */

const METHOD_AND_PATH = /^(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+(\/\S*)$/;
const HTTP_METHOD_LITERAL = /^(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)$/i;

/** Parameters that carry framework plumbing rather than a path segment. */
const PLUMBING_PARAMETER =
  /^_?(req|request|res|response|reply|ctx|context|next|url|event|options|opts|body|payload|parent|info|args|input|done)$/i;

/** Expressions that plausibly hold the request path. */
const PATH_BEARING = /pathname|\burl\b|\bpath\b|\broute\b|\btarget\b|\bendpoint\b|\bhref\b/i;

/** Keys under which a route table holds its matcher and its handler. */
const PATH_KEY = /^(path|pattern|route|match|matcher|url)$/i;
const HANDLER_KEY = /^(handler|handle|fn|action|controller|run)$/i;

interface DispatchEntry {
  method: string;
  path: string;
  /** Handlers this route dispatches to by name. */
  handlers: Set<string>;
  /** The branch or callback that implements the route, when it is inline. */
  node?: ts.Node;
}

const dispatchCache = new WeakMap<ts.SourceFile, DispatchEntry[]>();
const declarationCache = new WeakMap<ts.SourceFile, Map<string, ts.Expression>>();

/**
 * The endpoint a node belongs to, or undefined when this file does not say.
 *
 * Containment first, because a node inside a handler body settles it; then the
 * handler's own name against the dispatch table; then the nearest declared
 * route; then the file's own path for file-based routing.
 */
export function attributedRoute(context: RuleContext, node: ts.Node): string | undefined {
  const entries = dispatchTable(context);

  // Dispatch entries first: an `if` chain testing the method as well as the path
  // knows the verb, where route discovery records the same branch as `ANY`.
  for (const entry of entries) {
    if (entry.node && contains(entry.node, node)) return formatRoute(entry.method, entry.path);
  }
  for (const hint of context.routes) {
    if (hint.node && contains(hint.node, node)) return formatRoute(hint.method, hint.path);
  }

  const handler = enclosingNamed(node);
  const name = handler ? functionName(handler) : undefined;
  if (name) {
    for (const entry of entries) {
      if (!entry.handlers.has(name)) continue;
      return formatRoute(entry.method, nameParameters(entry.path, handler));
    }
    for (const hint of context.routes) {
      if (!hint.node || !calledByName(hint.node).has(name)) continue;
      return formatRoute(hint.method, nameParameters(hint.path, handler));
    }
  }

  const nearest = routeHintFor(context, node);
  if (nearest) return formatRoute(nearest.method, nearest.path);

  // `app/listings/[slug]/page.tsx` is one endpoint: a GET of its own path. The
  // component that implements it is a default export rather than a named `GET`,
  // which is why route discovery cannot see it.
  const filePath = routeFromFilePath(context.file.relativePath);
  if (filePath && /\/page\.[cm]?[jt]sx?$/.test(context.file.relativePath)) return `GET ${filePath}`;
  return undefined;
}

export function routeOf(context: RuleContext, node: ts.Node): { route?: string } {
  const route = attributedRoute(context, node);
  return route ? { route } : {};
}

function contains(container: ts.Node, node: ts.Node): boolean {
  return node.getStart() >= container.getStart() && node.getEnd() <= container.getEnd();
}

/** The nearest enclosing function that has a name worth matching. */
function enclosingNamed(node: ts.Node): ts.Node | undefined {
  let current = enclosingFunction(node);
  while (current) {
    if (functionName(current)) return current;
    current = enclosingFunction(current);
  }
  return undefined;
}

/** Functions this subtree calls by bare name. */
function calledByName(node: ts.Node): Set<string> {
  const names = new Set<string>();
  walk(node, (inner) => {
    if (ts.isCallExpression(inner) && ts.isIdentifier(inner.expression)) names.add(inner.expression.text);
  });
  return names;
}

/**
 * Give the path's parameters the names the handler uses.
 *
 * A pattern can only say that a segment is dynamic, so it comes back as `:id`.
 * The handler that receives it calls it `assetId`, and that is the name a reader
 * matches against the API documentation.
 */
function nameParameters(path: string, handler: ts.Node | undefined): string {
  if (!handler) return path;
  const dynamic = path.split("/").filter((segment) => segment.startsWith(":")).length;
  if (dynamic === 0) return path;
  const parameters = ((handler as ts.FunctionLikeDeclaration).parameters ?? [])
    .filter((parameter) => ts.isIdentifier(parameter.name) && !PLUMBING_PARAMETER.test(parameter.name.text))
    .map((parameter) => (parameter.name as ts.Identifier).text);
  if (parameters.length !== dynamic) return path;
  let index = 0;
  return path
    .split("/")
    .map((segment) => (segment.startsWith(":") ? `:${parameters[index++]}` : segment))
    .join("/");
}

/** Module-level bindings, so an identifier in a condition can be resolved. */
function declarationsIn(source: ts.SourceFile): Map<string, ts.Expression> {
  const cached = declarationCache.get(source);
  if (cached) return cached;
  const map = new Map<string, ts.Expression>();
  for (const declaration of collect(source, ts.isVariableDeclaration)) {
    if (!ts.isIdentifier(declaration.name) || !declaration.initializer) continue;
    if (!map.has(declaration.name.text)) map.set(declaration.name.text, declaration.initializer);
  }
  declarationCache.set(source, map);
  return map;
}

/** The source of a regular expression, whether written inline or bound to a name. */
function regexSourceOf(node: ts.Node, source: ts.SourceFile, depth = 0): string | null {
  if (ts.isRegularExpressionLiteral(node)) {
    const text = node.getText(source);
    const end = text.lastIndexOf("/");
    return end > 0 ? text.slice(1, end) : null;
  }
  if (ts.isNewExpression(node) && node.expression.getText(source) === "RegExp") {
    const first = node.arguments?.[0];
    return first && ts.isStringLiteralLike(first) ? first.text : null;
  }
  if (ts.isIdentifier(node) && depth < 3) {
    const initializer = declarationsIn(source).get(node.text);
    return initializer ? regexSourceOf(initializer, source, depth + 1) : null;
  }
  return null;
}

/** Regex metacharacters that mean a segment is a parameter, not a literal. */
const DYNAMIC_SEGMENT = /[\\[\](){}+*?|]|\\d|\\w|\\S|\.\+|\.\*/;

/** `^\/api\/media\/([0-9a-f-]{36})\/probe$` becomes `/api/media/:id/probe`. */
function pathFromRegexSource(pattern: string): string | null {
  let body = pattern.replace(/^\^/, "").replace(/\$$/, "").replace(/\\\//g, "/");
  if (!body.startsWith("/")) return null;
  const segments = body
    .slice(1)
    .split("/")
    .filter((segment) => segment.length > 0)
    .map((segment) => {
      const named = /^\(\?<([A-Za-z_][A-Za-z0-9_]*)>.*\)[?+*]?$/.exec(segment);
      if (named) return `:${named[1]}`;
      return DYNAMIC_SEGMENT.test(segment) ? ":id" : segment;
    });
  return segments.length === 0 ? "/" : `/${segments.join("/")}`;
}

/** The method and path an `if` condition selects, when it selects one. */
function conditionRoute(condition: ts.Expression, source: ts.SourceFile): { method?: string; path?: string } {
  let method: string | undefined;
  let path: string | undefined;

  const pathFromMatcher = (call: ts.CallExpression): string | undefined => {
    const tail = calleeTail(call);
    if (tail !== "test" && tail !== "exec" && tail !== "match") return undefined;
    if (!ts.isPropertyAccessExpression(call.expression)) return undefined;
    const receiver = call.expression.expression;
    const pattern =
      regexSourceOf(receiver, source) ??
      (tail === "match" ? regexSourceOf(call.arguments[0] ?? receiver, source) : null);
    if (!pattern) return undefined;
    const tested = tail === "match" ? receiver.getText(source) : (call.arguments[0]?.getText(source) ?? "");
    if (!PATH_BEARING.test(tested)) return undefined;
    return pathFromRegexSource(pattern) ?? undefined;
  };

  walk(condition, (node) => {
    if (ts.isCallExpression(node)) {
      path ??= pathFromMatcher(node);
      return;
    }
    // The condition may test the *result* of the match: `if (probe && ...)`.
    if (ts.isIdentifier(node) && !path) {
      const initializer = declarationsIn(source).get(node.text);
      if (initializer && ts.isCallExpression(initializer)) path ??= pathFromMatcher(initializer);
      return;
    }
    if (!ts.isBinaryExpression(node)) return;
    const isEquality =
      node.operatorToken.kind === ts.SyntaxKind.EqualsEqualsEqualsToken ||
      node.operatorToken.kind === ts.SyntaxKind.EqualsEqualsToken;
    if (!isEquality) return;
    for (const [side, other] of [
      [node.left, node.right],
      [node.right, node.left]
    ] as Array<[ts.Expression, ts.Expression]>) {
      const literal = literalTextOf(side);
      if (!literal) continue;
      if (HTTP_METHOD_LITERAL.test(literal) && /method/i.test(other.getText(source))) {
        method ??= literal.toUpperCase();
        continue;
      }
      if (!literal.startsWith("/")) continue;
      const otherText = other.getText(source);
      const resolved = ts.isIdentifier(other) ? (declarationsIn(source).get(other.text)?.getText(source) ?? "") : "";
      if (PATH_BEARING.test(otherText) || PATH_BEARING.test(resolved)) path ??= literal;
    }
  });

  return { ...(method ? { method } : {}), ...(path ? { path } : {}) };
}

/**
 * A route table written as data: `{ method, pattern, handler }` objects, or
 * `["POST /x", handler]` pairs inside an array or a Map.
 */
function tableEntries(source: ts.SourceFile): DispatchEntry[] {
  const entries: DispatchEntry[] = [];

  for (const literal of collect(source, ts.isObjectLiteralExpression)) {
    let method: string | undefined;
    let path: string | undefined;
    const handlers = new Set<string>();
    let inline: ts.Node | undefined;

    for (const property of literal.properties) {
      if (!ts.isPropertyAssignment(property)) continue;
      const key = property.name.getText(source).replace(/["']/g, "");
      const value = property.initializer;
      if (/^method$/i.test(key)) {
        const text = literalTextOf(value);
        if (text && HTTP_METHOD_LITERAL.test(text)) method = text.toUpperCase();
        continue;
      }
      if (PATH_KEY.test(key)) {
        const text = literalTextOf(value);
        if (text && text.startsWith("/")) path = text;
        else {
          const pattern = regexSourceOf(value, source);
          if (pattern) path = pathFromRegexSource(pattern) ?? undefined;
        }
        continue;
      }
      if (HANDLER_KEY.test(key)) {
        if (ts.isIdentifier(value)) handlers.add(value.text);
        if (ts.isArrowFunction(value) || ts.isFunctionExpression(value)) inline = value;
      }
    }

    if (!path || (handlers.size === 0 && !inline)) continue;
    entries.push({ method: method ?? "ANY", path, handlers, ...(inline ? { node: inline } : {}) });
  }

  // `new Map([["POST /api/wallet/withdrawals", requestWithdrawal]])`, and the
  // same table written as a plain array of pairs.
  for (const pair of collect(source, ts.isArrayLiteralExpression)) {
    if (pair.elements.length !== 2) continue;
    const key = literalTextOf(pair.elements[0]!);
    if (!key) continue;
    const match = METHOD_AND_PATH.exec(key);
    if (!match) continue;
    const value = pair.elements[1]!;
    const handlers = new Set<string>();
    if (ts.isIdentifier(value)) handlers.add(value.text);
    const inline = ts.isArrowFunction(value) || ts.isFunctionExpression(value) ? value : undefined;
    if (handlers.size === 0 && !inline) continue;
    entries.push({ method: match[1]!, path: match[2]!, handlers, ...(inline ? { node: inline } : {}) });
  }

  // `{ "POST /x": handler }`.
  for (const property of collect(source, ts.isPropertyAssignment)) {
    if (!ts.isStringLiteralLike(property.name)) continue;
    const match = METHOD_AND_PATH.exec(property.name.text);
    if (!match) continue;
    const handlers = new Set<string>();
    if (ts.isIdentifier(property.initializer)) handlers.add(property.initializer.text);
    const inline =
      ts.isArrowFunction(property.initializer) || ts.isFunctionExpression(property.initializer)
        ? property.initializer
        : undefined;
    entries.push({ method: match[1]!, path: match[2]!, handlers, ...(inline ? { node: inline } : {}) });
  }

  return entries;
}

function dispatchTable(context: RuleContext): DispatchEntry[] {
  const source = context.file.source;
  const cached = dispatchCache.get(source);
  if (cached) return cached;

  const entries = tableEntries(source);

  for (const clause of collect(source, ts.isCaseClause)) {
    const literal = literalTextOf(clause.expression);
    if (!literal) continue;
    const match = METHOD_AND_PATH.exec(literal);
    if (!match) continue;
    entries.push({ method: match[1]!, path: match[2]!, handlers: calledByName(clause), node: clause });
  }

  for (const statement of collect(source, ts.isIfStatement)) {
    const { method, path } = conditionRoute(statement.expression, source);
    if (!path) continue;
    entries.push({
      method: method ?? "ANY",
      path,
      handlers: calledByName(statement.thenStatement),
      node: statement.thenStatement
    });
  }

  dispatchCache.set(source, entries);
  return entries;
}
