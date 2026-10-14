import ts from "typescript";

import { IDENTITY_EVIDENCE } from "./records-origin.js";
import {
  calleeName,
  calleeTail,
  collect,
  dynamicParts,
  expressionName,
  isConstantString,
  literalTextOf,
  walk
} from "../ast/helpers.js";
import { lineOf, type ParsedFile } from "../ast/parse.js";
import { analyzeFunction, functionsIn, resolveExpression, rootOf, taintOrigin, type TaintScope } from "../ast/taint.js";
import { describeSink, formatRoute, locationOf, sourceEvidence, taintEvidence, type RouteHint, type Rule, type RuleContext } from "./context.js";

/**
 * The application's perimeter: what it reads, writes, fetches and redirects to,
 * and the limits it forgets.
 *
 * Everything in this file shares one discipline. A sink alone is never a finding:
 * the rule has to establish that a caller influences the value *and* that none of
 * the defences a competent engineer would have written is present. Those defences
 * are the reason the safe half of every pair in the corpus is safe, so recognising
 * them is not an optimisation — it is most of the work.
 */

/* ------------------------------------------------------------------------- *
 * Expression plumbing
 * ------------------------------------------------------------------------- */

/**
 * Strip the wrappers that carry no runtime meaning.
 *
 * `(await request.json()) as PreviewRequest` is the single most common way a
 * TypeScript handler reads its body, and a model that stops at the `as` loses the
 * whole flow behind it.
 */
function peel(node: ts.Node): ts.Node {
  let current = node;
  for (let depth = 0; depth < 8; depth += 1) {
    if (ts.isAsExpression(current) || ts.isSatisfiesExpression(current) || ts.isTypeAssertionExpression(current)) {
      current = current.expression;
      continue;
    }
    if (ts.isParenthesizedExpression(current) || ts.isNonNullExpression(current) || ts.isAwaitExpression(current)) {
      current = current.expression;
      continue;
    }
    return current;
  }
  return current;
}

function boundNames(pattern: ts.BindingName): string[] {
  if (ts.isIdentifier(pattern)) return [pattern.text];
  const names: string[] = [];
  for (const element of pattern.elements) {
    if (ts.isOmittedExpression(element)) continue;
    names.push(...boundNames(element.name));
  }
  return names;
}

/**
 * Re-run taint binding over a function body with type wrappers removed.
 *
 * The shared analyser builds the scope in one pass and cannot see through an `as`
 * cast, so a value read as `const body = (await request.json()) as T` never becomes
 * a root and every flow downstream of it disappears. Iterating to a fixed point
 * also removes the dependence on statement order.
 */
function augmentRoots(fn: ts.Node, scope: TaintScope): void {
  const body = (fn as ts.FunctionLikeDeclaration).body;
  if (!body) return;

  const record = (name: string, origin: string, declaration: ts.Node, initializer: ts.Expression): boolean => {
    // What produced a binding is recorded even when the shared pass already knew
    // the binding was tainted, because a destructured declaration leaves no
    // initializer entry and a rule then cannot find the helper it came out of.
    if (!scope.initializers.has(name)) scope.initializers.set(name, initializer);
    // A binding a guard has already cleared stays cleared: re-deriving taint for
    // it would undo exactly the validation this engine exists to respect.
    if (scope.cleared.has(name) || scope.roots.has(name)) return false;
    scope.roots.set(name, { name, origin, declaration });
    return true;
  };

  for (let pass = 0; pass < 5; pass += 1) {
    let changed = false;
    walk(body, (node) => {
      if (ts.isVariableDeclaration(node) && node.initializer) {
        const peeled = peel(node.initializer) as ts.Expression;
        const origin = taintOrigin(peeled, scope);
        if (!origin) return;
        for (const name of boundNames(node.name)) {
          if (record(name, origin, node, peeled)) changed = true;
        }
        return;
      }
      if (
        ts.isBinaryExpression(node) &&
        node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        ts.isIdentifier(node.left)
      ) {
        const peeled = peel(node.right) as ts.Expression;
        const origin = taintOrigin(peeled, scope);
        if (origin && record(node.left.text, origin, node, peeled)) changed = true;
      }
    });
    if (!changed) return;
  }
}

/** The taint scope for a function, with type wrappers followed. */
function scopeFor(file: ParsedFile, fn: ts.Node): TaintScope {
  const scope = analyzeFunction(file, fn);
  augmentRoots(fn, scope);
  return scope;
}

/**
 * Every function-like node, plus the module body.
 *
 * Cached per source file: rules ask for this once per sink, and re-walking the
 * whole tree each time turns a linear pass into a quadratic one on large files.
 */
const handlerCache = new WeakMap<ts.SourceFile, ts.Node[]>();

function handlersIn(file: ParsedFile): ts.Node[] {
  const cached = handlerCache.get(file.source);
  if (cached) return cached;
  const handlers = functionsIn(file.source);
  handlerCache.set(file.source, handlers);
  return handlers;
}

/** A function declared in this file under the given name, however it is written. */
function localFunction(file: ParsedFile, name: string): ts.Node | undefined {
  if (name.length === 0) return undefined;
  let found: ts.Node | undefined;
  walk(file.source, (node) => {
    if (found) return;
    if (ts.isFunctionDeclaration(node) && node.name?.text === name) {
      found = node;
      return;
    }
    // A class puts its validation in a method. `this.resolve(key)` confining a
    // path is the standard shape of an object-store driver, and a helper lookup
    // that only understands top-level functions reads it as unvalidated.
    if (ts.isMethodDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === name) {
      found = node;
      return;
    }
    if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      node.name.text === name &&
      node.initializer &&
      (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer))
    ) {
      found = node.initializer;
    }
  });
  return found;
}

/**
 * The local function a value came out of, when it came out of one.
 *
 * Real code puts its validation in a named helper — `landingPath(next)`,
 * `resolveWithinRoot(root, prefix, name)`, `resolveProvider(url)`. Reading the
 * helper is the difference between agreeing with correct code and shouting at it.
 */
function producingHelper(file: ParsedFile, expression: ts.Node, scope: TaintScope, depth = 0): ts.Node | undefined {
  if (depth > 3) return undefined;
  const resolved = peel(resolveExpression(peel(expression), scope));

  /*
   * `previewTarget(raw)` returns a URL; the fetch is given `target.toString()`.
   * Rendering a validated object back to a string is not a step away from the
   * helper that validated it, so the search continues through the renderer
   * rather than stopping at it — otherwise the correctly written form is the one
   * the rule reports, because the sloppy version passes the string straight
   * through and this one does not.
   */
  if (ts.isPropertyAccessExpression(resolved) && (resolved.name.text === "href" || resolved.name.text === "pathname")) {
    return producingHelper(file, resolved.expression, scope, depth + 1);
  }

  /*
   * `const target = raw ? previewTarget(raw) : null` — the helper sits inside a
   * conditional, and the branch that is not the helper is the one the caller
   * already refuses. Either branch may carry it, so both are tried.
   */
  if (ts.isConditionalExpression(resolved)) {
    return (
      producingHelper(file, resolved.whenTrue, scope, depth + 1) ??
      producingHelper(file, resolved.whenFalse, scope, depth + 1)
    );
  }
  if (ts.isBinaryExpression(resolved) && resolved.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken) {
    return (
      producingHelper(file, resolved.left, scope, depth + 1) ??
      producingHelper(file, resolved.right, scope, depth + 1)
    );
  }

  if (!ts.isCallExpression(resolved)) return undefined;

  if (
    ts.isPropertyAccessExpression(resolved.expression) &&
    resolved.expression.name.text === "toString" &&
    resolved.arguments.length === 0
  ) {
    return producingHelper(file, resolved.expression.expression, scope, depth + 1);
  }
  if (ts.isIdentifier(resolved.expression) && resolved.expression.text === "String" && resolved.arguments[0]) {
    return producingHelper(file, resolved.arguments[0], scope, depth + 1);
  }

  if (ts.isIdentifier(resolved.expression)) return localFunction(file, resolved.expression.text);
  if (
    ts.isPropertyAccessExpression(resolved.expression) &&
    resolved.expression.expression.kind === ts.SyntaxKind.ThisKeyword
  ) {
    return localFunction(file, resolved.expression.name.text);
  }
  return undefined;
}

/**
 * Was this value handed back by a function in another module?
 *
 * The engine follows data inside one function and says so in its own coverage
 * statement. A destination that came out of `safeRedirectPath(next)` — imported
 * from elsewhere — is not established as unvalidated, it is unread, and reporting
 * it as settled evidence is the kind of claim that teaches a reader to stop
 * believing the tool.
 */
function producedByUnreadableCall(file: ParsedFile, expression: ts.Node, scope: TaintScope): boolean {
  const resolved = peel(resolveExpression(peel(expression), scope));
  if (!ts.isCallExpression(resolved) || !ts.isIdentifier(resolved.expression)) return false;
  const name = resolved.expression.text;
  if (localFunction(file, name)) return false;
  return importedBindings(file).has(name);
}

/** Every name this file brings in from another module. */
function importedBindings(file: ParsedFile): Set<string> {
  const names = new Set<string>();
  for (const statement of file.source.statements) {
    if (!ts.isImportDeclaration(statement) || !statement.importClause) continue;
    const clause = statement.importClause;
    if (clause.name) names.add(clause.name.text);
    if (clause.namedBindings && ts.isNamedImports(clause.namedBindings)) {
      for (const element of clause.namedBindings.elements) names.add(element.name.text);
    }
    if (clause.namedBindings && ts.isNamespaceImport(clause.namedBindings)) names.add(clause.namedBindings.name.text);
  }
  walk(file.source, (node) => {
    if (!ts.isVariableDeclaration(node) || !node.initializer) return;
    const text = node.initializer.getText(file.source);
    if (!/\brequire\s*\(/.test(text)) return;
    for (const name of boundNames(node.name)) names.add(name);
  });
  return names;
}

/** The parameter names of a function, including destructured ones. */
function parameterNames(fn: ts.Node): Set<string> {
  const names = new Set<string>();
  for (const parameter of (fn as ts.FunctionLikeDeclaration).parameters ?? []) {
    for (const name of boundNames(parameter.name)) names.add(name);
  }
  return names;
}

function mentionsNames(expression: ts.Node, names: Set<string>): boolean {
  let mentions = false;
  walk(expression, (node) => {
    if (ts.isIdentifier(node) && names.has(node.text)) mentions = true;
  });
  return mentions;
}

/** Does this branch stop the handler, so a failed check cannot fall through? */
function branchStops(statement: ts.Node): boolean {
  let stops = false;
  walk(statement, (node) => {
    if (ts.isReturnStatement(node) || ts.isThrowStatement(node) || ts.isContinueStatement(node)) stops = true;
    // Koa and Fastify stop a request by calling, not by throwing a statement:
    // `ctx.throw(400, ...)` and `reply.code(400).send(...)` are the idiom, and a
    // guard model that only understands `throw` reads both as fall-through.
    if (ts.isCallExpression(node)) {
      const tail = calleeTail(node);
      if (tail === "throw" || tail === "abort" || tail === "unauthorized" || tail === "forbidden") stops = true;
    }
  });
  return stops;
}

/** Does one node sit inside another? */
function containsNode(container: ts.Node, node: ts.Node): boolean {
  return node.getStart() >= container.getStart() && node.getEnd() <= container.getEnd();
}

/**
 * Does this check decide whether the code after it runs?
 *
 * `if (!ALLOWED.has(parsed.hostname)) { log("not on the list"); }` reads exactly
 * like the correct guard and defends nothing: execution leaves the block and
 * reaches the sink with the caller's own value. A comparison only constrains
 * something when failing it stops the handler, or when the sink itself sits
 * inside the branch the comparison permits — so it is the shape of the branch,
 * and not the presence of the comparison, that the rule has to read.
 */
function checkDecidesFlow(check: ts.Node, region: ts.Node, sink: ts.Node | undefined): boolean {
  let current: ts.Node | undefined = check.parent;
  while (current && current !== region.parent) {
    if (ts.isIfStatement(current) && containsNode(current.expression, check)) {
      if (branchStops(current.thenStatement)) return true;
      if (current.elseStatement && branchStops(current.elseStatement)) return true;
      return sink !== undefined && containsNode(current, sink);
    }
    if (ts.isConditionalExpression(current) && containsNode(current.condition, check)) {
      return sink !== undefined && containsNode(current, sink);
    }
    current = current.parent;
  }
  // Not written as a condition at all: a table lookup whose miss yields undefined,
  // or a helper whose return value is the checked one. Those constrain by
  // construction rather than by branching, so there is no branch to inspect.
  return true;
}

/** Conditions that gate a node, from the innermost outwards. */
function gatingConditions(node: ts.Node, boundary: ts.Node): ts.Expression[] {
  const conditions: ts.Expression[] = [];
  let current: ts.Node | undefined = node.parent;
  while (current && current !== boundary.parent) {
    if (ts.isIfStatement(current)) conditions.push(current.expression);
    if (ts.isConditionalExpression(current)) conditions.push(current.condition);
    if (ts.isBinaryExpression(current) && current.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken) {
      conditions.push(current.left);
    }
    current = current.parent;
  }
  return conditions;
}

const MEMBERSHIP_METHODS = new Set(["has", "includes", "indexOf", "hasOwnProperty", "some", "find", "get"]);

/** Is this expression a lookup of `name` in a fixed set declared in this file? */
function testsMembershipOf(file: ParsedFile, expression: ts.Node, name: string): boolean {
  let found = false;
  walk(expression, (node) => {
    if (found) return;
    if (ts.isCallExpression(node)) {
      const tail = calleeTail(node);
      if (MEMBERSHIP_METHODS.has(tail)) {
        for (const argument of node.arguments) {
          if (rootOf(argument) === name) found = true;
        }
      }
      if (tail === "test" || tail === "match" || tail === "exec") {
        for (const argument of node.arguments) {
          if (rootOf(argument) === name) found = true;
        }
        if (ts.isPropertyAccessExpression(node.expression) && rootOf(node.expression.expression) === name) found = true;
      }
      return;
    }
    // `PROVIDERS[parsed.hostname]` and `TABLE[value]` are allowlists too.
    if (ts.isElementAccessExpression(node) && rootOf(node.argumentExpression) === name) {
      if (isConstantTable(file, node.expression)) found = true;
    }
    if (ts.isBinaryExpression(node)) {
      const isEquality =
        node.operatorToken.kind === ts.SyntaxKind.EqualsEqualsEqualsToken ||
        node.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsEqualsToken;
      if (!isEquality) return;
      if (rootOf(node.left) === name || rootOf(node.right) === name) found = true;
    }
  });
  return found;
}

/** A module-level constant holding a literal table, set, or list. */
function isConstantTable(file: ParsedFile, expression: ts.Node): boolean {
  const name = ts.isIdentifier(expression) ? expression.text : null;
  if (!name) return false;
  let constant = false;
  for (const statement of file.source.statements) {
    if (!ts.isVariableStatement(statement)) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (!ts.isIdentifier(declaration.name) || declaration.name.text !== name) continue;
      const initializer = declaration.initializer;
      if (!initializer) continue;
      if (ts.isObjectLiteralExpression(initializer) || ts.isArrayLiteralExpression(initializer)) constant = true;
      if (ts.isNewExpression(initializer)) {
        const built = expressionName(initializer.expression);
        if (built === "Set" || built === "Map") constant = true;
      }
    }
  }
  return constant;
}

/** A value produced only from literals or from a fixed table declared here. */
function returnsOnlyFixedValues(file: ParsedFile, fn: ts.Node): boolean {
  const body = (fn as ts.FunctionLikeDeclaration).body;
  if (!body) return false;
  const returns: ts.Expression[] = [];
  walk(body, (node) => {
    if (ts.isReturnStatement(node) && node.expression) returns.push(node.expression);
  });
  if (returns.length === 0) return false;

  const isFixed = (expression: ts.Node): boolean => {
    const value = peel(expression);
    if (ts.isStringLiteralLike(value) || ts.isNumericLiteral(value)) return true;
    if (value.kind === ts.SyntaxKind.NullKeyword) return true;
    if (ts.isIdentifier(value) && value.text === "undefined") return true;
    if (ts.isConditionalExpression(value)) return isFixed(value.whenTrue) && isFixed(value.whenFalse);
    if (ts.isBinaryExpression(value) && value.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken) {
      return isFixed(value.left) && isFixed(value.right);
    }
    // `match.extension`, where `match` came out of a literal signature table.
    if (ts.isPropertyAccessExpression(value) || ts.isElementAccessExpression(value)) {
      const root = rootOf(value);
      if (!root) return false;
      if (isConstantTable(file, ts.factory.createIdentifier(root))) return true;
      let fromTable = false;
      walk(body, (node) => {
        if (fromTable) return;
        if (!ts.isVariableDeclaration(node) || !ts.isIdentifier(node.name) || node.name.text !== root) return;
        if (!node.initializer) return;
        const source = rootOf(peel(node.initializer));
        if (source && isConstantTable(file, ts.factory.createIdentifier(source))) fromTable = true;
      });
      return fromTable;
    }
    return false;
  };

  return returns.every(isFixed);
}

/* ------------------------------------------------------------------------- *
 * Route attribution
 * ------------------------------------------------------------------------- */

const HTTP_METHOD_CALLS = new Set(["get", "post", "put", "patch", "delete", "options", "head", "all", "use"]);

/**
 * Route attribution beyond the shared discovery pass.
 *
 * Three gaps matter here and all three belong upstream in `ast/routes.ts`:
 * the receiver has to be one of a fixed list of names, so `attachments.get(...)`
 * in Hono and `widget.use(...)` are invisible; a parameter constraint such as
 * `:filename{.+}` is reported verbatim and no longer matches the route a reader
 * would write; and a sink in module-level middleware or a helper above the route
 * registrations gets no route at all even when the module declares exactly one.
 */
const routeCache = new WeakMap<ts.SourceFile, RouteHint[]>();

function perimeterRoutes(context: RuleContext): RouteHint[] {
  const cached = routeCache.get(context.file.source);
  if (cached) return cached;
  const hints: RouteHint[] = context.routes.map((hint) => ({ ...hint, path: normalizePath(hint.path) }));
  const seen = new Set(hints.map((hint) => `${hint.method} ${hint.path} ${hint.line}`));

  for (const call of collect(context.file.source, ts.isCallExpression)) {
    if (!ts.isPropertyAccessExpression(call.expression)) continue;
    const method = call.expression.name.text.toLowerCase();
    if (!HTTP_METHOD_CALLS.has(method)) continue;
    // Any local object can register a route: frameworks are configured through
    // whatever name the file gave the router.
    if (!ts.isIdentifier(call.expression.expression)) continue;
    const first = call.arguments[0];
    if (!first) continue;
    const literal = literalTextOf(first);
    if (!literal || !literal.startsWith("/")) continue;

    const hint: RouteHint = {
      method: method === "use" || method === "all" ? "ANY" : method.toUpperCase(),
      path: normalizePath(literal),
      line: lineOf(context.file, call)
    };
    const key = `${hint.method} ${hint.path} ${hint.line}`;
    if (seen.has(key)) continue;
    seen.add(key);
    hints.push(hint);
  }

  const sorted = hints.sort((a, b) => a.line - b.line);
  routeCache.set(context.file.source, sorted);
  return sorted;
}

/**
 * `/tickets/:filename{.+}` is the same route a reader calls `/tickets/:filename`.
 *
 * Only when the brace group is *attached* to the token before it, which is what makes
 * it a constraint. A group standing as its own segment is Hapi's parameter syntax —
 * `/api/notes/{noteId}` — and stripping it left `/api/notes/`, an address matching no
 * route and greppable for nothing. Mirrors `normalizePath` in `ast/routes.ts`; both
 * exist because the two stages resolve routes independently.
 */
function normalizePath(path: string): string {
  // A capture group, not a lookbehind: see the note in `ast/routes.ts`. The
  // lookbehind form cost more than half the scan time of a large file.
  return path.replace(/([^/\s])\s*\{[^}]*\}/g, "$1");
}

/**
 * A registration that mounts middleware over a group of paths rather than
 * declaring an endpoint. `app.use("/embed/*", cors(...))` says where a policy
 * applies, not what a caller can request, so it is never the answer to "which
 * route is this?" while a real endpoint is available.
 */
function isMount(hint: RouteHint): boolean {
  return hint.method === "ANY" || hint.path.includes("*");
}

/**
 * The route a sink belongs to.
 *
 * The nearest endpoint above wins. When there is none the nearest below is used,
 * because a sink in module-level middleware, or in an unpacking helper defined
 * above the route that calls it, still belongs to the routes of the module it is
 * written in — reporting no route there loses the only orientation a reader has.
 * Mounts are consulted only when the module declares no endpoint at all.
 */
function routeOf(context: RuleContext, node: ts.Node): string | undefined {
  const line = lineOf(context.file, node);
  const hints = perimeterRoutes(context);

  const nearest = (candidates: RouteHint[]): RouteHint | undefined => {
    let above: RouteHint | undefined;
    let below: RouteHint | undefined;
    for (const hint of candidates) {
      if (hint.line <= line && (!above || hint.line > above.line)) above = hint;
      if (hint.line > line && (!below || hint.line < below.line)) below = hint;
    }
    return above ?? below;
  };

  const best = nearest(hints.filter((hint) => !isMount(hint))) ?? nearest(hints);
  if (best) return formatRoute(best.method, best.path);

  // A resolver map is reached through the GraphQL endpoint rather than through a
  // route of its own, and saying nothing is less true than saying that.
  if (isGraphqlModule(context.file)) return "POST /graphql";
  return undefined;
}

function isGraphqlModule(file: ParsedFile): boolean {
  let declaresResolvers = false;
  walk(file.source, (node) => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name)) {
      if (node.name.text === "resolvers" || node.name.text === "typeDefs") declaresResolvers = true;
    }
  });
  return declaresResolvers;
}

function withRoute(context: RuleContext, node: ts.Node): { route: string } | Record<string, never> {
  const route = routeOf(context, node);
  return route ? { route } : {};
}

/* ------------------------------------------------------------------------- *
 * Open redirect
 * ------------------------------------------------------------------------- */

const REDIRECT_TAILS = new Set(["redirect", "Redirect"]);

type GuardStrength = "none" | "weak" | "strong";

function strongest(a: GuardStrength, b: GuardStrength): GuardStrength {
  if (a === "strong" || b === "strong") return "strong";
  if (a === "weak" || b === "weak") return "weak";
  return "none";
}

/**
 * The destination a redirect actually sends the browser to.
 *
 * `NextResponse.redirect(new URL("/sign-in?error=x", request.nextUrl.origin))` is
 * the framework's own way of writing a fixed same-origin redirect. The base is the
 * application's own origin, so the only thing that can move the browser off this
 * site is the relative reference — reading the whole `new URL(...)` as
 * caller-controlled reports four safe redirects per sign-in route.
 */
function redirectDestination(argument: ts.Expression): ts.Expression {
  const peeled = peel(argument);
  if (ts.isNewExpression(peeled) && expressionName(peeled.expression) === "URL") {
    const first = peeled.arguments?.[0];
    if (first) return first;
  }
  return peeled as ts.Expression;
}

/** A value whose leading literal is already an absolute same-site path. */
function hasSameSitePrefix(expression: ts.Node): boolean {
  const node = peel(expression);
  if (ts.isTemplateExpression(node)) return isSameSiteLiteral(node.head.text);
  if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    const head = literalTextOf(peel(node.left));
    if (head !== null) return isSameSiteLiteral(head);
    return hasSameSitePrefix(node.left);
  }
  const literal = literalTextOf(node);
  return literal === null ? false : isSameSiteLiteral(literal);
}

function isSameSiteLiteral(text: string): boolean {
  // A single leading slash followed by something that is not a slash or a
  // backslash cannot be re-pointed at another origin by anything appended to it.
  return /^\/[^/\\]/.test(text);
}

/** Literal arguments a call was given, for reading what a check tests for. */
function literalArguments(call: ts.CallExpression): string[] {
  return call.arguments.map((argument) => literalTextOf(peel(argument))).filter((text): text is string => text !== null);
}

/**
 * How well a body constrains a redirect destination to this site.
 *
 * `startsWith("/")` on its own is the check everybody writes and it is not enough:
 * `//evil.example` begins with a slash. Rejecting the second slash, the backslash
 * form, or an embedded scheme is what makes it correct — and resolving the value
 * against the application origin and comparing origins is stronger still.
 */
function redirectGuardStrength(file: ParsedFile, region: ts.Node, subject: string | null): GuardStrength {
  let requiresPath = false;
  let rejectsForeign = false;
  let comparesOrigin = false;
  let resolvesAgainstBase = false;

  // With no subject the whole region is the check — that is the case when the
  // region *is* the validating helper and its parameter is the value.
  const concerns = (node: ts.Node): boolean => subject === null || rootOf(node) === subject;

  walk(region, (node) => {
    if (ts.isNewExpression(node) && expressionName(node.expression) === "URL" && (node.arguments?.length ?? 0) > 1) {
      resolvesAgainstBase = true;
    }
    // Reading `.origin` proves nothing; comparing it to something does.
    if (ts.isPropertyAccessExpression(node) && /^(origin|host|hostname)$/.test(node.name.text)) {
      if (isComparedOrTested(node)) comparesOrigin = true;
    }

    if (!ts.isCallExpression(node)) return;
    const tail = calleeTail(node);
    const receiver = ts.isPropertyAccessExpression(node.expression) ? node.expression.expression : null;

    if ((tail === "startsWith" || tail === "includes" || tail === "indexOf") && receiver && concerns(receiver)) {
      for (const text of literalArguments(node)) {
        if (text === "/") requiresPath = true;
        else if (text.includes("//") || text.includes("\\") || text.includes(":")) rejectsForeign = true;
      }
    }

    // Membership in a fixed set of destinations settles it in both directions.
    if (MEMBERSHIP_METHODS.has(tail) && receiver && isConstantTable(file, receiver)) {
      if (node.arguments.some((argument) => concerns(argument))) {
        requiresPath = true;
        rejectsForeign = true;
      }
    }

    if (tail === "test" && receiver) {
      const source = regexSource(file, receiver);
      const argument = node.arguments[0];
      if (source && argument && concerns(argument)) {
        if (/^\^\\?\//.test(source)) requiresPath = true;
        if (/\(\?!|\[\^/.test(source)) rejectsForeign = true;
      }
    }
  });

  // Resolving the value against this application's origin and then requiring the
  // resolved origin to match is the form that has no edge cases.
  if (comparesOrigin && resolvesAgainstBase) return "strong";
  if (requiresPath && rejectsForeign) return "strong";
  if (requiresPath) return "weak";
  return "none";
}

/** Is this expression one side of an equality, or an argument to a membership test? */
function isComparedOrTested(node: ts.Node): boolean {
  const parent = node.parent;
  if (!parent) return false;
  if (ts.isBinaryExpression(parent)) {
    const kind = parent.operatorToken.kind;
    return kind === ts.SyntaxKind.EqualsEqualsEqualsToken || kind === ts.SyntaxKind.ExclamationEqualsEqualsToken;
  }
  if (ts.isCallExpression(parent)) return MEMBERSHIP_METHODS.has(calleeTail(parent));
  return false;
}

/** The source text of a regular expression, written inline or held in a constant. */
function regexSource(file: ParsedFile, node: ts.Node): string | null {
  if (ts.isRegularExpressionLiteral(node)) {
    const text = node.getText(file.source);
    const end = text.lastIndexOf("/");
    return end > 0 ? text.slice(1, end) : null;
  }
  if (ts.isNewExpression(node) && expressionName(node.expression) === "RegExp") {
    const first = node.arguments?.[0];
    return first ? literalTextOf(first) : null;
  }
  if (ts.isIdentifier(node)) {
    for (const declaration of collect(file.source, ts.isVariableDeclaration)) {
      if (!ts.isIdentifier(declaration.name) || declaration.name.text !== node.text) continue;
      if (declaration.initializer) return regexSource(file, declaration.initializer);
    }
  }
  return null;
}

/** Properties of a URL object that decide which site it points at. */
const ORIGIN_PROPERTIES = /^(href|host|hostname|origin|protocol|port|username|password)$/;

/**
 * The value a destination ultimately is, past the accessors that only render it.
 *
 * `authorize.toString()` and `authorize.href` *are* the URL that was built rather
 * than a new value derived from it, so the question "what fixed this origin" has
 * to be asked of the binding behind them.
 */
function renderedValueOf(expression: ts.Node, scope: TaintScope): ts.Node {
  let current = peel(resolveExpression(peel(expression), scope));
  for (let depth = 0; depth < 4; depth += 1) {
    if (ts.isCallExpression(current) && ts.isPropertyAccessExpression(current.expression)) {
      const tail = calleeTail(current);
      if (tail === "toString" || tail === "toJSON") {
        current = peel(resolveExpression(peel(current.expression.expression), scope));
        continue;
      }
    }
    if (ts.isPropertyAccessExpression(current) && current.name.text === "href") {
      current = peel(resolveExpression(peel(current.expression), scope));
      continue;
    }
    break;
  }
  return current;
}

/** Was this URL binding re-pointed at another site after it was built? */
function originReassigned(fn: ts.Node, name: string): boolean {
  let reassigned = false;
  walk(fn, (node) => {
    if (reassigned) return;
    if (!ts.isBinaryExpression(node) || node.operatorToken.kind !== ts.SyntaxKind.EqualsToken) return;
    if (ts.isIdentifier(node.left) && node.left.text === name) reassigned = true;
    if (
      ts.isPropertyAccessExpression(node.left) &&
      rootOf(node.left) === name &&
      ORIGIN_PROPERTIES.test(node.left.name.text)
    ) {
      reassigned = true;
    }
  });
  return reassigned;
}

/**
 * Is this destination a URL whose origin was fixed when it was constructed?
 *
 * `new URL("https://idp.example/oauth/authorize")` decides scheme and host at
 * construction, and the `searchParams.set(...)` calls that follow write only the
 * query — a query string cannot move the browser to another site. Taint tracking
 * has to treat a receiver that accumulates caller data as tainted, which makes
 * the redirect to the identity provider, the correct half of every OAuth flow,
 * look caller-chosen. Reading how the URL was built is what tells the two apart,
 * so the check refuses a binding that anything later re-points.
 */
function urlOriginFixedAtConstruction(fn: ts.Node, expression: ts.Node, scope: TaintScope): boolean {
  const value = renderedValueOf(expression, scope);
  if (!ts.isNewExpression(value) || expressionName(value.expression) !== "URL") return false;
  const first = value.arguments?.[0];
  // With a base argument the reference decides whether the origin holds, which is
  // a different question; here only a self-contained absolute URL counts.
  if (value.arguments && value.arguments.length > 1) return false;
  if (!first || !isConstantString(first)) return false;
  if (!/^https?:\/\/[^/\s]+/.test(literalTextOf(peel(first)) ?? "")) return false;
  const binding = rootOf(peel(expression));
  return binding === null || !originReassigned(fn, binding);
}

/** Response statuses whose Location header moves the browser. */
const REDIRECT_STATUSES = new Set(["301", "302", "303", "307", "308"]);

const LOCATION_HEADER = /^location$/i;

/** The name a header map or an options object gives a property, quotes removed. */
function propertyKey(file: ParsedFile, property: ts.PropertyAssignment): string {
  return property.name.getText(file.source).replace(/["'`]/g, "");
}

/** The `location` entry of a header map written as an object literal. */
function locationHeaderOf(file: ParsedFile, headers: ts.Expression): ts.Expression | undefined {
  const node = peel(headers);
  if (!ts.isObjectLiteralExpression(node)) return undefined;
  for (const property of node.properties) {
    if (!ts.isPropertyAssignment(property)) continue;
    if (LOCATION_HEADER.test(propertyKey(file, property))) return property.initializer;
  }
  return undefined;
}

/**
 * A redirect written as a response rather than as a call.
 *
 * Outside Express there is no `res.redirect`: an edge worker, a fetch handler and
 * a web-platform route all move the browser by returning a 3xx response with a
 * Location header. It is the same defect in a different spelling, and a rule that
 * only knows the method call is blind to it in every runtime that builds its own
 * response — which is most of them.
 */
function responseRedirectDestination(file: ParsedFile, node: ts.Node): ts.Expression | undefined {
  if (!ts.isNewExpression(node) || expressionName(node.expression) !== "Response") return undefined;
  const init = node.arguments?.[1] ? peel(node.arguments[1]!) : undefined;
  if (!init || !ts.isObjectLiteralExpression(init)) return undefined;

  let redirects = false;
  let location: ts.Expression | undefined;
  for (const property of init.properties) {
    if (!ts.isPropertyAssignment(property)) continue;
    const key = propertyKey(file, property);
    if (key === "status" && REDIRECT_STATUSES.has(peel(property.initializer).getText(file.source))) redirects = true;
    if (key === "headers") location = locationHeaderOf(file, property.initializer);
  }
  // Without a 3xx status the Location header is inert, and without the header the
  // status moves nothing; only the pair is a redirect.
  return redirects ? location : undefined;
}

interface RedirectSite {
  /** The node the finding is reported at. */
  node: ts.Node;
  /** The value that decides where the browser ends up. */
  destination: ts.Expression;
  /** How the sink is named in the finding's own prose. */
  sink: string;
}

/** Every place this function sends the browser somewhere. */
function redirectSites(file: ParsedFile, fn: ts.Node): RedirectSite[] {
  const sites: RedirectSite[] = [];
  walk(fn, (node) => {
    if (ts.isCallExpression(node) && REDIRECT_TAILS.has(calleeTail(node))) {
      const first = node.arguments[0];
      if (first) sites.push({ node, destination: redirectDestination(first), sink: describeSink(node) });
      return;
    }
    const location = responseRedirectDestination(file, node);
    if (location) {
      sites.push({ node, destination: redirectDestination(location), sink: "the Location header of a 3xx response" });
    }
  });
  return sites;
}

export const redirectDestinationUnvalidated: Rule = {
  id: "perimeter-open-redirect",
  category: "open_redirect",
  describes: "caller-supplied redirect destinations that are not constrained to this site",
  run(context: RuleContext) {
    // One sink sits inside several nested scopes. Reporting it once per enclosing
    // function would describe one defect several times.
    const reported = new Set<number>();
    for (const fn of handlersIn(context.file)) {
      const scope = scopeFor(context.file, fn);

      for (const site of redirectSites(context.file, fn)) {
        const call = site.node;
        const destination = site.destination;
        if (isConstantString(destination)) continue;
        if (hasSameSitePrefix(destination)) continue;
        if (urlOriginFixedAtConstruction(fn, destination, scope)) continue;

        const origin = taintOrigin(destination, scope);
        if (!origin) continue;

        const root = rootOf(destination);
        if (root && scope.allowlisted.has(root)) continue;

        let strength = redirectGuardStrength(context.file, fn, root);
        const helper = producingHelper(context.file, destination, scope);
        if (helper) strength = strongest(strength, redirectGuardStrength(context.file, helper, null));
        if (strength === "strong") continue;
        if (!helper && producedByUnreadableCall(context.file, destination, scope)) continue;
        if (reported.has(lineOf(context.file, call))) continue;
        reported.add(lineOf(context.file, call));

        const weak = strength === "weak";
        context.report({
          ruleId: "perimeter-open-redirect",
          category: "open_redirect",
          title: weak
            ? "Redirect destination is guarded only by a leading-slash check, which a protocol-relative URL satisfies"
            : "Redirect destination is caller-supplied and never constrained to this site",
          severity: "medium",
          verification: "strong_evidence",
          summary: weak
            ? `The destination given to ${site.sink} comes from ${origin} and the only check on it is a leading-slash test. A value beginning with two slashes is a protocol-relative URL: it passes that test and still sends the browser to another origin.`
            : `The destination given to ${site.sink} comes from ${origin}. Nothing between the read and the redirect requires it to be a path on this site — no allowlist, no single-leading-slash test, and no comparison of the resolved origin against this application's own.`,
          impact:
            "A link on this application's own domain sends the visitor to a site the attacker controls. Placed at the end of a sign-in flow it is a credential-phishing primitive of unusual quality, because the hop happens from the origin the victim has just trusted with a password.",
          remediation:
            "Constrain the value before it is used. Either resolve it against this application's origin and discard it unless the resolved origin matches, or require a single leading slash and reject a second slash, a backslash, and any embedded scheme. Keep that decision in one helper so every redirect in the codebase inherits it.",
          verificationPlan:
            "Drive the flow with a destination of `//example.test`, then with `/\\\\example.test`, and confirm the browser stays on this origin and the response's Location header points at a path on this site.",
          taxonomy: ["CWE-601", "OWASP-A01"],
          location: locationOf(context, call),
          ...withRoute(context, call),
          evidence: [
            sourceEvidence(context, call, "The redirect target is derived from caller input."),
            taintEvidence(origin, site.sink)
          ],
          reasoning: weak
            ? `Taint from ${origin} reaches ${site.sink}; the only guard found on its root binding is startsWith("/"), which a protocol-relative URL satisfies.`
            : `Taint from ${origin} reaches ${site.sink}; no allowlist, leading-slash-plus-double-slash test, or resolved-origin comparison was found on its root binding or in the helper that produced it.`
        });
      }
    }
  }
};

/* ------------------------------------------------------------------------- *
 * Path traversal
 * ------------------------------------------------------------------------- */

/**
 * Sinks that read, write, or hand out file contents.
 *
 * `stat` and `readdir` are deliberately absent. They disclose whether a path
 * exists, which is a much smaller thing than reading it, and a download route
 * almost always stats a path immediately before reading it — reporting both turns
 * one defect into two findings a line apart and makes the report read like noise.
 */
const PATH_SINKS = new Map<string, number[]>([
  ["readFile", [0]],
  ["readFileSync", [0]],
  ["createReadStream", [0]],
  ["writeFile", [0]],
  ["writeFileSync", [0]],
  ["appendFile", [0]],
  ["appendFileSync", [0]],
  ["createWriteStream", [0]],
  ["unlink", [0]],
  ["unlinkSync", [0]],
  ["rm", [0]],
  ["rmSync", [0]],
  ["rmdir", [0]],
  ["truncate", [0]],
  ["copyFile", [0, 1]],
  ["copyFileSync", [0, 1]],
  ["cp", [0, 1]],
  ["rename", [0, 1]],
  ["renameSync", [0, 1]],
  ["sendFile", [0]],
  ["download", [0]]
]);


const PATH_JOINERS = new Set(["join", "resolve", "normalize"]);

/** Transforms whose result cannot contain a path separator. */
const SEGMENT_NEUTRALIZERS = new Set(["basename", "extname"]);

/** String methods that pass a value through without being able to add separators. */
const SEPARATOR_SAFE_METHODS = new Set([
  "toLowerCase",
  "toUpperCase",
  "trim",
  "trimStart",
  "trimEnd",
  "normalize",
  "padStart",
  "padEnd",
  "toString"
]);

/** Property names a multipart parser fills in with a path it chose itself. */
const PARSER_OWNED_PATHS = /^(filepath|filePath|tempFilePath|tmpPath|tmpName|path|destination)$/;

/** Is this expression a path being assembled out of parts? */
function composesPath(node: ts.Node): boolean {
  if (ts.isCallExpression(node) && PATH_JOINERS.has(calleeTail(node))) return true;
  if (ts.isTemplateExpression(node)) return true;
  return ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken;
}

/**
 * The individual values that make up a path expression.
 *
 * A local binding is followed only when it holds a *composition* of a path. Going
 * further and replacing every identifier with the expression it was built from
 * throws away the name a guard was written against, so a value pinned by
 * `PATTERN.test(tag)` arrives here as `String(req.body.tag).trim()` and the guard
 * can no longer be found.
 */
function pathSegments(expression: ts.Node, scope: TaintScope): ts.Expression[] {
  const node = peel(expression);

  if (ts.isCallExpression(node) && PATH_JOINERS.has(calleeTail(node))) {
    return node.arguments.flatMap((argument) => pathSegments(argument, scope));
  }
  if (ts.isTemplateExpression(node) || ts.isBinaryExpression(node)) {
    const parts = dynamicParts(node);
    if (parts.length > 0) return parts.flatMap((part) => pathSegments(part, scope));
  }
  if (ts.isIdentifier(node)) {
    const initializer = scope.initializers.get(node.text);
    if (initializer && composesPath(peel(initializer))) return pathSegments(initializer, scope);
  }
  return [node as ts.Expression];
}

/**
 * Is this segment unable to escape the directory it is joined onto?
 *
 * `path.basename` is a real defence and has to silence the rule: it removes every
 * separator, so what is left cannot address a parent directory. The check has to
 * be structural, though. Both vulnerable download routes in the corpus call
 * `path.basename(filename)` — for the Content-Disposition header, while joining the
 * raw value into the path they then read. A rule that looks for the *presence* of
 * basename anywhere in the handler agrees with the wrong half of the file.
 */
function segmentIsContained(
  context: RuleContext,
  fn: ts.Node,
  segment: ts.Node,
  scope: TaintScope,
  depth = 0
): boolean {
  if (depth > 4) return true;
  const node = peel(segment);

  if (ts.isCallExpression(node)) {
    const tail = calleeTail(node);
    if (SEGMENT_NEUTRALIZERS.has(tail)) return true;
    if (SEPARATOR_SAFE_METHODS.has(tail) && ts.isPropertyAccessExpression(node.expression)) {
      return segmentIsContained(context, fn, node.expression.expression, scope, depth + 1);
    }
    const helper = producingHelper(context.file, node, scope);
    if (
      helper &&
      (helperContainsPaths(helper) ||
        helperPinsParameters(context.file, helper) ||
        returnsOnlyFixedValues(context.file, helper))
    ) {
      return true;
    }

    /*
     * A path built inside a function is confined when every tainted argument is confined.
     *
     * Without this the guard is lost the moment the join moves into a helper: the finding
     * lands at the call site, on the binding the call produced — a fresh name no guard ever
     * touched — and the rule answers "not contained" for a value that was validated one line
     * earlier. Extracting path resolution into a confining helper is the single most
     * recommended fix for traversal, so the engine reported the advice it gives.
     *
     * A helper cannot invent a traversal out of constrained inputs. If it does, that is a
     * defect in the helper and belongs to the helper's own case, reported where the unsafe
     * join actually is rather than at every call site that passes a validated string.
     */
    const carried = node.arguments.filter((argument) => taintOrigin(argument, scope) !== null);
    if (carried.length > 0) {
      return carried.every((argument) => segmentIsContained(context, fn, argument, scope, depth + 1));
    }
  }

  // A multipart parser chose this path, not the caller: the client controls the
  // declared file name, never the temporary location the parser wrote it to.
  if (ts.isPropertyAccessExpression(node) && PARSER_OWNED_PATHS.test(node.name.text)) {
    const root = rootOf(node);
    if (root && uploadBindings(context.file, fn).has(root)) return true;
  }

  if (ts.isIdentifier(node)) {
    const root = node.text;
    if (scope.containmentChecked.has(root) || scope.allowlisted.has(root) || scope.cleared.has(root)) return true;
    if (hasCharsetGuard(context.file, fn, root)) return true;
    if (establishedByAuthentication(context, scope, root)) return true;

    const initializer = scope.initializers.get(root);
    if (!initializer) return false;
    const parts = pathSegments(initializer, scope);
    const tainted = parts.filter((part) => taintOrigin(part, scope) !== null);
    if (tainted.length === 0) return true;
    return tainted.every((part) => part !== node && segmentIsContained(context, fn, part, scope, depth + 1));
  }

  if (ts.isTemplateExpression(node) || ts.isBinaryExpression(node)) {
    const parts = dynamicParts(node).filter((part) => taintOrigin(part, scope) !== null);
    if (parts.length === 0) return true;
    return parts.every((part) => segmentIsContained(context, fn, part, scope, depth + 1));
  }

  const root = rootOf(node);
  if (root && (scope.containmentChecked.has(root) || scope.allowlisted.has(root))) return true;
  return false;
}

/**
 * Was this binding produced by the call that establishes who is asking?
 *
 * `const { tenantId } = requireTenant(req)` reads the tenant off `req.user`, which the
 * authentication layer sets and no client can supply. The taint model treats everything
 * reachable from `req` as caller-controlled — right by default, and wrong here — so the
 * tenant read as attacker-chosen and a correctly scoped download became the reported defect.
 * That is the worst way for this rule to be wrong: a confident finding on code doing the
 * right thing.
 *
 * `IDENTITY_EVIDENCE` is the vocabulary the ownership rules already use for this exact
 * question, and it already lists the call. Reused rather than reinvented, and general rather
 * than shaped to one case — a list of identity-establishing calls applied uniformly.
 *
 * Deliberately narrow: only a binding whose own declaration *is* that call. A value merely
 * derived from the subject further down is not covered, because widening this is how a rule
 * stops seeing paths that really are attacker-chosen.
 */
function establishedByAuthentication(context: RuleContext, scope: TaintScope, root: string): boolean {
  const declaration = scope.roots.get(root)?.declaration;
  if (!declaration || !ts.isVariableDeclaration(declaration) || !declaration.initializer) return false;
  const initializer = peel(declaration.initializer);
  const call = ts.isAwaitExpression(initializer) ? peel(initializer.expression) : initializer;
  if (!ts.isCallExpression(call)) return false;
  const callee = ts.isPropertyAccessExpression(call.expression) ? call.expression.name.text : call.expression;
  const name = typeof callee === "string" ? callee : ts.isIdentifier(callee) ? callee.text : null;
  if (name === null) return false;

  /*
   * The shape answer first: this call was traced, in the file that defines it, to a return
   * built only from server-owned properties of its own parameters. That holds whatever the
   * function is called.
   *
   * `IDENTITY_EVIDENCE` stays as a fallback for the calls the index cannot reach — a helper
   * in a file the scan did not parse, or one re-exported through a chain. It is the narrower
   * answer, because it only ever knows the names on its list.
   */
  if (context.serverOwnedCalls?.has(name)) return true;
  return IDENTITY_EVIDENCE.test(name);
}

/** Does this helper resolve a path and confine it, or reduce it to a basename? */
function helperContainsPaths(helper: ts.Node): boolean {
  let reducesToBasename = false;
  let resolves = false;
  let confines = false;
  walk(helper, (node) => {
    if (!ts.isCallExpression(node)) return;
    const tail = calleeTail(node);
    if (tail === "basename") reducesToBasename = true;
    if (tail === "resolve") resolves = true;
    if (tail === "startsWith" || tail === "relative") confines = true;
  });
  return reducesToBasename || (resolves && confines);
}

/**
 * Regular-expression escapes that cannot stand for a path separator.
 *
 * `\.` is a dot and `\w` is a word character; neither can be a slash. An escape
 * outside this list — a code point, a back-reference, `\S`, `\W`, `\D` — either is
 * a separator or can match one, and an escape the rule cannot read has to count
 * against the guard rather than for it.
 */
const SEPARATOR_FREE_ESCAPES = /^[dwsbBnrtfv.^$*+?()[\]{}|\-]$/;

/**
 * Can a value matching this pattern carry a path separator?
 *
 * The question is not whether the source text contains a slash or a backslash.
 * `^[A-Za-z0-9_-]{1,64}\.csv$` contains a backslash and matches only a dot, so
 * reading the text rejects an entirely correct guard and the route it protects
 * gets reported. What decides containment is which characters the pattern can
 * match, so the pattern has to be read as a pattern.
 */
function patternAdmitsSeparator(source: string): boolean {
  let index = 0;
  while (index < source.length) {
    const char = source[index];
    if (char === "\\") {
      const escaped = source[index + 1];
      if (escaped === undefined || !SEPARATOR_FREE_ESCAPES.test(escaped)) return true;
      index += 2;
      continue;
    }
    // An unescaped dot matches every character but a line break, separators
    // included, which is what makes `.` and `.*` worthless in a containment guard.
    if (char === "/" || char === ".") return true;
    if (char === "[") {
      const end = characterClassEnd(source, index);
      if (end === -1) return true;
      if (classAdmitsSeparator(source.slice(index + 1, end))) return true;
      index = end + 1;
      continue;
    }
    index += 1;
  }
  return false;
}

/** The index of the `]` that closes the character class opening at `start`. */
function characterClassEnd(source: string, start: number): number {
  let index = start + 1;
  if (source[index] === "^") index += 1;
  // A `]` written first in a class is a literal bracket, not the terminator.
  if (source[index] === "]") index += 1;
  while (index < source.length) {
    if (source[index] === "\\") {
      index += 2;
      continue;
    }
    if (source[index] === "]") return index;
    index += 1;
  }
  return -1;
}

/** Does this character class body match `/` or `\`? */
function classAdmitsSeparator(body: string): boolean {
  const negated = body.startsWith("^");
  const members = negated ? body.slice(1) : body;

  const matches = (code: number): boolean => {
    let index = 0;
    while (index < members.length) {
      if (members[index] === "\\") {
        const escaped = members[index + 1];
        if (escaped === undefined) return true;
        if (escaped === "/" || escaped === "\\") {
          if (code === escaped.charCodeAt(0)) return true;
        } else if (!SEPARATOR_FREE_ESCAPES.test(escaped)) {
          return true;
        }
        index += 2;
        continue;
      }
      const first = members.charCodeAt(index);
      if (members[index + 1] === "-" && index + 2 < members.length) {
        if (code >= first && code <= members.charCodeAt(index + 2)) return true;
        index += 3;
        continue;
      }
      if (code === first) return true;
      index += 1;
    }
    return false;
  };

  const slash = matches("/".charCodeAt(0));
  const backslash = matches("\\".charCodeAt(0));
  // A negated class admits everything it does not list, so it carries a separator
  // unless it excludes both spellings of one.
  return negated ? !(slash && backslash) : slash || backslash;
}

/**
 * Does an anchored pattern hold a value to one name inside its directory?
 *
 * Two things take a joined value out of the base directory: a separator, and a
 * parent-directory hop written without one. The first is answered by reading the
 * pattern; the second by asking the pattern itself whether it accepts `..`, which
 * is exact and needs no reasoning about what the character classes contain.
 */
function patternConfinesToOneSegment(source: string): boolean {
  if (patternAdmitsSeparator(source)) return false;
  try {
    return !new RegExp(source).test("..");
  } catch {
    return false;
  }
}

/**
 * The binding a guard is really testing, past the coercions written around it.
 *
 * `PATTERN.test(String(id))` and `PATTERN.test(id.trim())` test exactly the value
 * that is about to be joined onto the base directory. Reading only the outermost
 * expression finds `String` where the subject is `id`, and a correct validation
 * then counts for nothing.
 */
function guardSubjectRoot(expression: ts.Node, depth = 0): string | null {
  const node = peel(expression);
  if (depth < 4 && ts.isCallExpression(node)) {
    const tail = calleeTail(node);
    const first = node.arguments[0];
    // A free coercion takes the value as its argument, a method as its receiver.
    if (first && ts.isIdentifier(node.expression) && (tail === "String" || SEPARATOR_SAFE_METHODS.has(tail))) {
      return guardSubjectRoot(first, depth + 1);
    }
    if (SEPARATOR_SAFE_METHODS.has(tail) && ts.isPropertyAccessExpression(node.expression)) {
      return guardSubjectRoot(node.expression.expression, depth + 1);
    }
  }
  return rootOf(node);
}

/**
 * Does this helper refuse anything its callers could use to leave the base
 * directory?
 *
 * A directory resolver is normally written once and reused: `libraryDir(id)`
 * rejects an id that is not an anchored slug and only then joins it onto the
 * root, so the value handed back could never have carried a separator. The guard
 * lives in the helper rather than at the sink, and a check that reads only the
 * calling function sees a composed path with no validation anywhere near it.
 */
function helperPinsParameters(file: ParsedFile, helper: ts.Node): boolean {
  const parameters = [...parameterNames(helper)];
  if (parameters.length === 0) return false;
  // Every parameter, not merely one: an unpinned parameter is a way in, and the
  // rule cannot tell from here which of them reaches the join.
  return parameters.every((name) => hasCharsetGuard(file, helper, name));
}

/**
 * A terminating guard that pins a value to a character set with no separators.
 *
 * `if (!LABEL_PATTERN.test(label)) return res.status(400)...` where the pattern is
 * `^[a-z0-9][a-z0-9-]{0,39}$` is a complete defence against traversal: the value
 * cannot contain a slash, a backslash, or a dot. Treating it as no defence at all
 * is how a scanner ends up reporting a correctly written export route.
 */
/**
 * Does this condition reject a parent-directory hop outright?
 *
 * Only `||` disjuncts count, and only in a condition that stops the handler: in
 * `if (!PATTERN.test(leaf) || leaf.includes("..")) return`, either disjunct being true ends
 * the request, so the `includes` closes the parent-segment hole on its own. Under `&&` it
 * would close nothing, because the handler continues whenever the other side is false.
 */
function conditionRejectsParent(condition: ts.Node, name: string): boolean {
  const disjuncts: ts.Node[] = [];
  const flatten = (node: ts.Node): void => {
    const inner = peel(node);
    if (ts.isBinaryExpression(inner) && inner.operatorToken.kind === ts.SyntaxKind.BarBarToken) {
      flatten(inner.left);
      flatten(inner.right);
      return;
    }
    disjuncts.push(inner);
  };
  flatten(condition);

  return disjuncts.some((disjunct) => {
    if (!ts.isCallExpression(disjunct)) return false;
    const tail = calleeTail(disjunct);
    if (tail !== "includes" && tail !== "startsWith" && tail !== "indexOf") return false;
    if (!ts.isPropertyAccessExpression(disjunct.expression)) return false;
    if (guardSubjectRoot(disjunct.expression.expression) !== name) return false;
    const argument = disjunct.arguments[0];
    return Boolean(argument && ts.isStringLiteral(argument) && argument.text.includes(".."));
  });
}

function hasCharsetGuard(file: ParsedFile, fn: ts.Node, name: string): boolean {
  let guarded = false;
  walk(fn, (node) => {
    if (guarded) return;
    if (!ts.isIfStatement(node)) return;
    if (!branchStops(node.thenStatement) && !(node.elseStatement && branchStops(node.elseStatement))) return;
    walk(node.expression, (inner) => {
      if (guarded) return;
      if (!ts.isCallExpression(inner)) return;
      if (calleeTail(inner) !== "test" || !ts.isPropertyAccessExpression(inner.expression)) return;
      const argument = inner.arguments[0];
      if (!argument || guardSubjectRoot(argument) !== name) return;
      const source = regexSource(file, inner.expression.expression);
      if (!source) return;
      // The pattern has to be anchored at both ends *and* unable to express a
      // separator or a parent-directory hop; an unanchored pattern says only that
      // the value contains something acceptable, not that it is nothing else.
      if (!source.startsWith("^") || !source.endsWith("$")) return;
      /*
       * The pattern alone is enough when it can express neither a separator nor a parent hop.
       * When it merely excludes separators — which any character class containing `.` does —
       * the condition beside it has to close the `..` hole explicitly. Reading the regex on
       * its own discards half of a guard that is sound as a whole.
       */
      if (!patternConfinesToOneSegment(source)) {
        if (patternAdmitsSeparator(source)) return;
        if (!conditionRejectsParent(node.expression, name)) return;
      }
      guarded = true;
    });
  });
  return guarded;
}

export const filesystemPathTraversal: Rule = {
  id: "perimeter-path-traversal",
  category: "path_traversal",
  describes: "caller-supplied path segments reaching a filesystem read, write, or send",
  run(context: RuleContext) {
    const reported = new Set<number>();
    for (const fn of handlersIn(context.file)) {
      const scope = scopeFor(context.file, fn);

      for (const call of collect(fn, ts.isCallExpression)) {
        const tail = calleeTail(call);
        const positions = PATH_SINKS.get(tail);
        if (!positions) continue;
        const name = calleeName(call);

        for (const position of positions) {
          const argument = call.arguments[position];
          if (!argument) continue;

          const origin = taintOrigin(argument, scope);
          if (!origin) continue;

          // Containment on the finished path is the correct fix and the safe half
          // of every pair in the corpus uses it.
          const root = rootOf(argument);
          if (root && (scope.containmentChecked.has(root) || scope.allowlisted.has(root))) continue;

          const helper = producingHelper(context.file, argument, scope);
          if (helper && (helperContainsPaths(helper) || helperPinsParameters(context.file, helper))) continue;

          const segments = pathSegments(argument, scope).filter((segment) => taintOrigin(segment, scope) !== null);
          const escaping = segments.filter((segment) => !segmentIsContained(context, fn, segment, scope));
          // Nothing caller-supplied survives the decomposition: every part of the
          // path is either the application's own or one a guard already reduced to
          // a bare name. A binding can still carry taint from a read that a later
          // check narrowed to a single property, and reporting on that alone is a
          // claim about a segment the rule cannot name — which is the shape of an
          // accusation a reader cannot check.
          if (escaping.length === 0) continue;
          if (reported.has(lineOf(context.file, call))) continue;
          reported.add(lineOf(context.file, call));

          const joiner = joinerUsedFor(argument, scope);
          const segmentText = escaping[0] ? escaping[0].getText(context.file.source) : argument.getText(context.file.source);

          context.report({
            ruleId: "perimeter-path-traversal",
            category: "path_traversal",
            title: `Caller-supplied path segment reaches ${name} with no containment check`,
            severity: "high",
            verification: "strong_evidence",
            summary: joiner
              ? `\`${segmentText}\`, derived from ${origin}, is combined with a base directory using ${joiner} and passed to ${name}. Joining constrains nothing: a parent-directory segment walks straight out of the base directory, and nothing here reduces the value to a bare file name or checks that the resolved path stayed inside.`
              : `\`${segmentText}\`, derived from ${origin}, is passed to ${name} without any check that the resolved path stays inside an intended directory.`,
            impact:
              "An attacker reads or overwrites files outside the intended directory using the process's own credentials — environment files, private keys, session stores, and the application's own source. On a write or delete sink it is also a way to corrupt the deployment.",
            remediation:
              "Reduce the caller's contribution to a single name with `path.basename`, or resolve the candidate path and reject it unless it is inside the base directory compared with a trailing separator. Addressing files by an opaque identifier that maps to a stored path is stronger still, because the caller then has no influence over the path at all.",
            verificationPlan:
              "Request the same route with a segment of `../../etc/passwd`, then with its URL-encoded and double-encoded forms, and confirm each is refused with no file contents and no difference in timing that reveals whether the path exists.",
            taxonomy: ["CWE-22", "CWE-23", "OWASP-A01"],
            location: locationOf(context, pathCompositionSite(argument, scope) ?? call),
            ...withRoute(context, call),
            evidence: [
              sourceEvidence(context, call, `${name} receives a path built from caller input with no containment check.`),
              taintEvidence(origin, describeSink(call))
            ],
            reasoning: `Taint from ${origin} reaches argument ${position} of ${name}; the contributing segment is neither reduced by path.basename nor confined by a resolve-and-startsWith check, an allowlist, or an anchored character-set guard.`
          });
          break;
        }
      }
    }
  }
};

function joinerUsedFor(argument: ts.Node, scope: TaintScope): string | null {
  const resolved = peel(resolveExpression(peel(argument), scope));
  if (ts.isCallExpression(resolved) && PATH_JOINERS.has(calleeTail(resolved))) return `${calleeName(resolved)}()`;
  return null;
}

/**
 * Where the caller's segment was accepted, which is where the fix goes.
 *
 * `createReadStream(absolute)` is the read. There is nothing to change on that
 * line: `absolute` is already wrong by the time it arrives. The defect, and the
 * remediation, are at the join that accepted a caller-supplied segment without
 * confining it —
 *
 *     const absolute = path.join(bundleRoot, params.key);   // the finding
 *     ...
 *     createReadStream(absolute)                            // reported here before
 *
 * Falls back to the sink when the path was not composed locally, because then the
 * sink really is the most specific thing this rule can point at.
 */
function pathCompositionSite(argument: ts.Node, scope: TaintScope): ts.Node | null {
  const resolved = peel(resolveExpression(peel(argument), scope));
  if (ts.isCallExpression(resolved) && PATH_JOINERS.has(calleeTail(resolved))) return resolved;
  return null;
}

/* ------------------------------------------------------------------------- *
 * Zip slip
 * ------------------------------------------------------------------------- */

const ARCHIVE_LIBRARIES = /yauzl|unzipper|adm-zip|adm_zip|node-stream-zip|jszip|extract-zip|decompress|tar\b|unzip/i;
const ENTRY_NAME_PROPERTIES = /^(fileName|filename|entryName|name|path)$/;
const ARCHIVE_WRITE_SINKS = new Set([
  "createWriteStream",
  "writeFile",
  "writeFileSync",
  "appendFile",
  "copyFile",
  "mkdir",
  "mkdirSync",
  "rename",
  "extract",
  "extractAllTo"
]);

/** Does this file open archives at all? */
function handlesArchives(file: ParsedFile): boolean {
  for (const statement of file.source.statements) {
    if (ts.isImportDeclaration(statement) && ts.isStringLiteralLike(statement.moduleSpecifier)) {
      if (ARCHIVE_LIBRARIES.test(statement.moduleSpecifier.text)) return true;
    }
  }
  let seen = false;
  walk(file.source, (node) => {
    if (seen) return;
    if (ts.isCallExpression(node)) {
      const name = calleeName(node);
      if (/require\(/.test(name)) return;
      if (/openReadStream|getEntries|fromBuffer|readEntry|entryStream/.test(name)) seen = true;
    }
    if (ts.isCallExpression(node) && calleeTail(node) === "require") {
      const first = node.arguments[0];
      const text = first ? literalTextOf(first) : null;
      if (text && ARCHIVE_LIBRARIES.test(text)) seen = true;
    }
  });
  return seen;
}

/** Callback parameters and loop bindings that hold one archive entry. */
function archiveEntryBindings(file: ParsedFile): Map<string, ts.Node> {
  const bindings = new Map<string, ts.Node>();

  walk(file.source, (node) => {
    if (ts.isCallExpression(node)) {
      const tail = calleeTail(node);
      if (tail === "on" || tail === "once" || tail === "forEach" || tail === "map") {
        const event = node.arguments[0] ? literalTextOf(node.arguments[0]!) : null;
        const callback = node.arguments.find(
          (argument) => ts.isArrowFunction(argument) || ts.isFunctionExpression(argument)
        ) as ts.FunctionLikeDeclaration | undefined;
        if (!callback) return;
        const receiverText = ts.isPropertyAccessExpression(node.expression)
          ? node.expression.expression.getText(file.source)
          : "";
        const isEntryStream = event === "entry" || event === "file";
        const isEntryList = /getEntries\(\)|\.entries\b|\.files\b/.test(receiverText);
        if (!isEntryStream && !isEntryList) return;
        const parameter = callback.parameters[0];
        if (parameter && ts.isIdentifier(parameter.name)) bindings.set(parameter.name.text, callback);
      }
      return;
    }
    if (ts.isForOfStatement(node)) {
      const source = node.expression.getText(file.source);
      if (!/getEntries\(\)|\.entries\b|\.files\b|archive|zip|entries/i.test(source)) return;
      const declaration = node.initializer;
      if (!ts.isVariableDeclarationList(declaration)) return;
      for (const binding of declaration.declarations) {
        for (const name of boundNames(binding.name)) bindings.set(name, node.statement);
      }
    }
  });

  return bindings;
}

/** Does anything in this region confine the joined entry path? */
function entryPathConfined(region: ts.Node, target: string | null, entryName: string): boolean {
  let confined = false;
  walk(region, (node) => {
    if (confined) return;
    if (!ts.isCallExpression(node)) return;
    const tail = calleeTail(node);
    const receiverRoot = ts.isPropertyAccessExpression(node.expression) ? rootOf(node.expression.expression) : null;

    if (tail === "basename") {
      for (const argument of node.arguments) {
        if (rootOf(argument) === entryName) confined = true;
      }
    }
    if (tail === "startsWith" && receiverRoot && (receiverRoot === target || receiverRoot === entryName)) confined = true;
    if (tail === "relative") confined = true;
    if ((tail === "includes" || tail === "indexOf" || tail === "startsWith") && receiverRoot === entryName) {
      for (const text of literalArguments(node)) {
        if (text.includes("..") || text.includes("/") || text.includes("\\")) confined = true;
      }
    }
    if (tail === "test") {
      const argument = node.arguments[0];
      if (argument && rootOf(argument) === entryName) confined = true;
    }
  });
  return confined;
}

export const archiveEntryEscape: Rule = {
  id: "perimeter-zip-slip",
  category: "zip_slip",
  describes: "archive entry names joined onto a destination directory and written unchecked",
  run(context: RuleContext) {
    if (!handlesArchives(context.file)) return;
    const entries = archiveEntryBindings(context.file);
    if (entries.size === 0) return;

    const reported = new Set<number>();

    for (const [entryName, region] of entries) {
      for (const declaration of collect(region, ts.isVariableDeclaration)) {
        if (!ts.isIdentifier(declaration.name) || !declaration.initializer) continue;
        const initializer = peel(declaration.initializer);
        if (!mentionsEntryName(initializer, entryName)) continue;

        const target = declaration.name.text;
        if (!writtenTo(region, target)) continue;

        // The correct form resolves each entry against the destination and skips
        // anything that lands outside it. That may be inline or in a helper.
        if (entryPathConfined(region, target, entryName)) continue;
        const helperName = ts.isCallExpression(initializer) && ts.isIdentifier(initializer.expression)
          ? initializer.expression.text
          : null;
        const helper = helperName ? localFunction(context.file, helperName) : undefined;
        if (helper && helperContainsPaths(helper)) continue;

        const line = lineOf(context.file, declaration);
        if (reported.has(line)) continue;
        reported.add(line);

        context.report({
          ruleId: "perimeter-zip-slip",
          category: "zip_slip",
          title: "Archive entry name is joined onto the destination directory and written without a containment check",
          severity: "high",
          verification: "strong_evidence",
          summary: `Each entry's own name is combined with the unpack directory to produce \`${target}\`, and the result is written to disk. An entry name inside an archive is attacker-supplied data like any other: a name of \`../../etc/cron.d/job\` or an absolute path resolves outside the destination, and nothing here checks that the resolved target stayed inside it.`,
          impact:
            "An uploaded archive writes files anywhere the process can write. Overwriting a template, a configuration file, a systemd unit, or a file inside a directory the web server executes turns an import feature into remote code execution.",
          remediation:
            "Resolve every entry against the resolved destination directory and skip — do not sanitise, skip — any entry whose resolved path is not inside it, comparing with a trailing separator. Reject absolute entry names and symbolic-link entries outright, and bound the entry count and uncompressed size while you are there.",
          verificationPlan:
            "Upload an archive containing an entry named `../../../tmp/myrqen-probe` and confirm the file is not created outside the destination directory and the import reports the entry as skipped.",
          taxonomy: ["CWE-22", "CWE-29", "OWASP-A01"],
          location: locationOf(context, declaration),
          ...withRoute(context, declaration),
          evidence: [
            sourceEvidence(context, declaration, "The unpack target is built from the archive entry's own name."),
            {
              kind: "source",
              description: `\`${entryName}\` is the entry object handed to the unpack loop, so \`${entryName}\`'s name comes from inside the uploaded archive and not from the application.`
            }
          ],
          reasoning: `Entry binding \`${entryName}\` contributes its name to \`${target}\`, which reaches a filesystem write; no resolve-and-startsWith containment, path.basename reduction, or parent-directory rejection was found in the unpack loop or in the helper that built the path.`
        });
      }
    }
  }
};

function mentionsEntryName(expression: ts.Node, entryName: string): boolean {
  let mentions = false;
  walk(expression, (node) => {
    if (mentions) return;
    if (ts.isPropertyAccessExpression(node) && ENTRY_NAME_PROPERTIES.test(node.name.text)) {
      if (rootOf(node) === entryName) mentions = true;
    }
    if (ts.isIdentifier(node) && node.text === entryName && ts.isCallExpression(node.parent)) mentions = true;
  });
  return mentions;
}

function writtenTo(region: ts.Node, target: string): boolean {
  let written = false;
  walk(region, (node) => {
    if (written) return;
    if (!ts.isCallExpression(node)) return;
    if (!ARCHIVE_WRITE_SINKS.has(calleeTail(node))) return;
    for (const argument of node.arguments) {
      if (rootOf(argument) === target) written = true;
    }
  });
  return written;
}

/* ------------------------------------------------------------------------- *
 * Unrestricted file upload
 * ------------------------------------------------------------------------- */

/** Expression shapes that hand back an uploaded file. */
const UPLOAD_SOURCES = /\.file\s*\(|\.files\b|\.file\b|\.parts\s*\(|formData\s*\.\s*get\s*\(|\.single\s*\(|\.array\s*\(/;

/** Properties of an uploaded file that the client, not the server, chose. */
const CLIENT_CHOSEN_PROPERTIES = /^(filename|fileName|originalname|originalName|originalFilename|name|mimetype|mimeType|type|contentType)$/;

/** Sinks that put an upload on disk, with the position of the destination path. */
const UPLOAD_WRITE_SINKS = new Map<string, number>([
  ["createWriteStream", 0],
  ["writeFile", 0],
  ["writeFileSync", 0],
  ["appendFile", 0],
  ["copyFile", 1],
  ["copyFileSync", 1],
  ["rename", 1],
  ["mv", 0],
  ["move", 0]
]);

/** Local bindings that hold an uploaded file. */
function uploadBindings(file: ParsedFile, fn: ts.Node): Map<string, string> {
  const bindings = new Map<string, string>();
  const body = (fn as ts.FunctionLikeDeclaration).body;
  if (!body) return bindings;

  walk(body, (node) => {
    if (ts.isVariableDeclaration(node) && node.initializer && ts.isIdentifier(node.name)) {
      const text = peel(node.initializer).getText(file.source);
      if (UPLOAD_SOURCES.test(text)) bindings.set(node.name.text, text);
      return;
    }
    if (ts.isForOfStatement(node) && UPLOAD_SOURCES.test(node.expression.getText(file.source))) {
      if (!ts.isVariableDeclarationList(node.initializer)) return;
      for (const declaration of node.initializer.declarations) {
        for (const name of boundNames(declaration.name)) bindings.set(name, node.expression.getText(file.source));
      }
    }
  });
  return bindings;
}

/** The client-chosen upload properties that feed this expression. */
function clientChosenParts(expression: ts.Node, uploads: Map<string, string>, scope: TaintScope): ts.PropertyAccessExpression[] {
  const found: ts.PropertyAccessExpression[] = [];
  const seen = new Set<ts.Node>();

  const visit = (node: ts.Node, depth: number): void => {
    if (depth > 5 || seen.has(node)) return;
    seen.add(node);
    const resolved = peel(resolveExpression(peel(node), scope));
    walk(resolved, (inner) => {
      if (ts.isPropertyAccessExpression(inner) && CLIENT_CHOSEN_PROPERTIES.test(inner.name.text)) {
        const root = rootOf(inner);
        if (root && uploads.has(root)) found.push(inner);
      }
      if (ts.isIdentifier(inner) && inner !== resolved && scope.initializers.has(inner.text)) {
        visit(inner, depth + 1);
      }
    });
  };

  visit(expression, 0);
  return found;
}

/**
 * Is the stored file's type pinned to something the server decided?
 *
 * The correct upload handler maps a verified content type onto an extension it
 * chose itself. Reading the extension off the client's file name and trusting it
 * is what turns an avatar field into stored cross-site scripting.
 */
function uploadTypeConstrained(file: ParsedFile, fn: ts.Node): boolean {
  let constrained = false;
  walk(fn, (node) => {
    if (constrained) return;
    // `ALLOWED_IMAGE_TYPES[upload.mimetype]` — a fixed table keyed by the type.
    if (ts.isElementAccessExpression(node) && isConstantTable(file, node.expression)) {
      const key = node.argumentExpression.getText(file.source);
      if (/mimetype|mimeType|contentType|content-type|\btype\b|extension|\bext\b/i.test(key)) constrained = true;
      return;
    }
    if (!ts.isCallExpression(node)) return;
    const tail = calleeTail(node);
    if (!MEMBERSHIP_METHODS.has(tail) && tail !== "test") return;
    const receiver = ts.isPropertyAccessExpression(node.expression) ? node.expression.expression : null;
    if (!receiver || !isConstantTable(file, receiver)) return;
    const argumentText = node.arguments.map((argument) => argument.getText(file.source)).join(", ");
    if (/mimetype|mimeType|contentType|content-type|\btype\b|extension|\bext\b/i.test(argumentText)) constrained = true;
  });
  return constrained;
}

/**
 * Does the destination directory look like one a web server hands out directly?
 *
 * It changes what the bug is: a file in a served directory is stored cross-site
 * scripting the moment it lands, while one behind a handler that sets its own
 * content type is a narrower problem. The name is often only in the constant's
 * value, so the constant has to be resolved rather than read off the expression.
 */
function looksWebServed(file: ParsedFile, expression: ts.Node): boolean {
  const served = /public|www|static|assets|cdn|htdocs|webroot/i;
  let looks = false;
  walk(expression, (node) => {
    if (looks || !ts.isIdentifier(node)) return;
    if (served.test(node.text)) {
      looks = true;
      return;
    }
    const constant = moduleConstant(file, node.text);
    if (constant && served.test(constant.getText(file.source))) looks = true;
  });
  return looks;
}

export const unrestrictedFileUpload: Rule = {
  id: "perimeter-unrestricted-upload",
  category: "unrestricted_file_upload",
  describes: "uploads stored under a client-chosen name or type with no allowlist",
  run(context: RuleContext) {
    const reported = new Set<number>();
    for (const fn of handlersIn(context.file)) {
      const scope = scopeFor(context.file, fn);
      const uploads = uploadBindings(context.file, fn);
      if (uploads.size === 0) continue;
      if (uploadTypeConstrained(context.file, fn)) continue;

      for (const call of collect(fn, ts.isCallExpression)) {
        const tail = calleeTail(call);
        const position = UPLOAD_WRITE_SINKS.get(tail);
        if (position === undefined) continue;
        const destination = call.arguments[position];
        if (!destination) continue;

        const parts = clientChosenParts(destination, uploads, scope);
        if (parts.length === 0) continue;

        if (reported.has(lineOf(context.file, call))) break;
        reported.add(lineOf(context.file, call));

        const contributions = [...new Set(parts.map((part) => part.getText(context.file.source)))];
        const servedPublicly = looksWebServed(context.file, destination);

        context.report({
          ruleId: "perimeter-unrestricted-upload",
          category: "unrestricted_file_upload",
          title: "Uploaded file is stored under a client-chosen name or extension with no type allowlist",
          severity: "high",
          verification: "needs_review",
          summary: `The destination this upload is written to is built from ${contributions.map((text) => `\`${text}\``).join(" and ")}, so the client decides the stored file's name or its extension. Nothing in this handler compares the declared content type against a fixed list, and nothing pins the extension to a type the server verified.${servedPublicly ? " The destination directory is named as one that is served to the web, so whatever lands there is reachable by URL." : ""}`,
          impact:
            "An attacker uploads a file whose extension makes the server or the browser treat it as something other than the content type the feature exists for. Served back from this application's origin, an `.html` or `.svg` upload is stored cross-site scripting against every viewer; where the directory is executed by the runtime, it is remote code execution.",
          remediation:
            "Generate the stored name yourself from an opaque identifier and keep the client's name only as display metadata. Derive the extension from a content type you have checked against an allowlist — and confirm it against the file's own leading bytes, because the declared type is caller input too. Bound the accepted size, store outside any directory the web server serves directly, and set an explicit Content-Type and `Content-Disposition: attachment` when handing the file back.",
          verificationPlan:
            "Upload a file named `probe.html` containing a script tag, with a content type of `image/png`, and confirm the stored object is a generated name with a server-chosen extension and that fetching it returns a non-HTML content type that the browser does not render.",
          taxonomy: ["CWE-434", "CWE-646", "OWASP-A04"],
          location: locationOf(context, call),
          ...withRoute(context, call),
          evidence: [
            sourceEvidence(context, call, "The upload is written to a path built from client-supplied file metadata."),
            {
              kind: "source",
              description: `No allowlist of content types or extensions appears in this handler: neither a membership test nor a fixed table keyed by the declared type constrains what may be stored.`
            }
          ],
          reasoning: `An uploaded file binding contributes ${contributions.join(", ")} to the destination of ${calleeName(call)}; no constant-table lookup or membership guard on the declared type or extension was found in the handler.`
        });
        break;
      }
    }
  }
};

/* ------------------------------------------------------------------------- *
 * Server-side request forgery
 * ------------------------------------------------------------------------- */

const FETCH_NAMES = new Set([
  "fetch",
  "axios",
  "got",
  "ky",
  "undici.request",
  "http.request",
  "https.request",
  "http.get",
  "https.get",
  "request"
]);

const FETCH_METHODS = new Set(["fetch", "request", "get", "post", "put", "patch", "head", "del", "delete", "stream"]);
const FETCH_RECEIVERS = /axios|got|ky|undici|https?$|client|fetcher|http|agent|webhook|image/i;

function isOutboundRequest(file: ParsedFile, call: ts.CallExpression): boolean {
  const name = calleeName(call);
  if (FETCH_NAMES.has(name)) return true;
  const tail = calleeTail(call);
  if (!FETCH_METHODS.has(tail)) return false;
  if (!ts.isPropertyAccessExpression(call.expression)) return false;
  const receiver = call.expression.expression.getText(file.source);
  return FETCH_RECEIVERS.test(receiver);
}

/** The destination of an outbound request, whether positional or in a config object. */
function outboundDestination(call: ts.CallExpression): ts.Expression | undefined {
  const first = call.arguments[0];
  if (!first) return undefined;
  const peeled = peel(first);
  if (ts.isObjectLiteralExpression(peeled)) {
    for (const property of peeled.properties) {
      if (!ts.isPropertyAssignment(property)) continue;
      const name = property.name.getText();
      if (name === "url" || name === "uri" || name === "baseURL") return property.initializer;
    }
    return undefined;
  }
  return peeled as ts.Expression;
}

/** A value whose leading literal already fixes scheme and host. */
function hasFixedOrigin(expression: ts.Node): boolean {
  const node = peel(expression);
  if (ts.isTemplateExpression(node)) return /^https?:\/\/[^/\s{}]+\//.test(node.head.text);
  if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    const head = literalTextOf(peel(node.left));
    if (head !== null) return /^https?:\/\/[^/\s{}]+\//.test(head);
    return hasFixedOrigin(node.left);
  }
  return false;
}

/**
 * Does this region pin the destination's host to something the server chose?
 *
 * The check has to *decide* the request, not merely appear before it. An
 * allow-list comparison whose failing branch logs a warning and falls through is
 * the most convincing-looking way to get this wrong, and it leaves the caller in
 * charge of the host exactly as if the comparison were not there.
 */
function hostConstrained(file: ParsedFile, region: ts.Node, subject: string | null, sink?: ts.Node): boolean {
  let constrained = false;
  const accept = (node: ts.Node): void => {
    if (checkDecidesFlow(node, region, sink)) constrained = true;
  };

  walk(region, (node) => {
    if (constrained) return;

    if (ts.isElementAccessExpression(node) && isConstantTable(file, node.expression)) {
      if (/hostname|host|origin|domain/i.test(node.argumentExpression.getText(file.source))) accept(node);
      return;
    }
    if (ts.isBinaryExpression(node)) {
      const isEquality =
        node.operatorToken.kind === ts.SyntaxKind.EqualsEqualsEqualsToken ||
        node.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsEqualsToken;
      if (isEquality && /\.(hostname|host|origin)\b/.test(node.getText(file.source))) accept(node);
      return;
    }
    if (!ts.isCallExpression(node)) return;
    const tail = calleeTail(node);
    if (!MEMBERSHIP_METHODS.has(tail) && tail !== "test") return;
    const argumentText = node.arguments.map((argument) => argument.getText(file.source)).join(", ");
    if (/hostname|host|origin|domain/i.test(argumentText)) {
      accept(node);
      return;
    }
    if (subject && node.arguments.some((argument) => rootOf(argument) === subject)) {
      const receiver = ts.isPropertyAccessExpression(node.expression) ? node.expression.expression : null;
      if (receiver && isConstantTable(file, receiver)) accept(node);
    }
  });
  return constrained;
}

/**
 * Does this helper build its URL onto a base the caller cannot influence?
 *
 * An object-store or upstream-API driver takes a key or an identifier and composes
 * it into a path under an endpoint it read from configuration. The caller extends
 * the path and never names the host, which is not request forgery. The condition
 * has to be exact, because `new URL(callerValue, base)` with an *absolute* caller
 * value discards the base entirely — so the relative reference must be one the
 * caller cannot make absolute or protocol-relative.
 */
function helperFixesOrigin(file: ParsedFile, helper: ts.Node): boolean {
  const parameters = parameterNames(helper);
  const scope = scopeFor(file, helper);
  const callerSupplied = (node: ts.Node) => mentionsNames(node, parameters);
  let composed = false;
  let fixed = false;

  walk(helper, (node) => {
    if (!ts.isNewExpression(node) || expressionName(node.expression) !== "URL") return;
    const reference = node.arguments?.[0];
    const base = node.arguments?.[1];
    if (!reference || !base) return;
    composed = true;
    // A base the caller chose is no base at all.
    if (callerSupplied(base)) return;
    if (staysRelative(file, reference, scope, callerSupplied)) fixed = true;
  });

  return composed && fixed;
}

/**
 * Is this destination a reference resolved against an origin the caller cannot
 * name?
 *
 * `new URL(`/oembed/${slug}.json`, "https://docs.example.com")` reaches a fixed
 * upstream over a caller-chosen path, which is not request forgery: the base
 * decides scheme and host and the caller only extends the path. Written inline in
 * the handler rather than inside a resolver it is the same construction, and a
 * rule that only reads it through a helper reports every correct upstream call on
 * a web-platform runtime. The condition stays exact, because an *absolute*
 * reference discards the base entirely.
 */
function resolvedOnFixedOrigin(file: ParsedFile, expression: ts.Node, scope: TaintScope): boolean {
  const resolved = peel(resolveExpression(peel(expression), scope));
  if (!ts.isNewExpression(resolved) || expressionName(resolved.expression) !== "URL") return false;
  const reference = resolved.arguments?.[0];
  const base = resolved.arguments?.[1];
  if (!reference || !base) return false;
  const callerSupplied = (node: ts.Node) => taintOrigin(node, scope) !== null;
  // A base the caller can influence is no base at all.
  if (callerSupplied(base)) return false;
  return staysRelative(file, reference, scope, callerSupplied);
}

/** Can this reference never be read as absolute or protocol-relative? */
function staysRelative(
  file: ParsedFile,
  reference: ts.Node,
  scope: TaintScope,
  callerSupplied: (node: ts.Node) => boolean
): boolean {
  const node = peel(resolveExpression(peel(reference), scope));
  const literal = literalTextOf(node);
  if (literal !== null) return isSameSiteLiteral(literal);
  // `"/oembed/" + slug + ".json"` is the same construction as the template, and
  // the leading literal decides it in exactly the same way. Reading only
  // templates loses the half of the codebases that concatenate.
  if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    const head = literalTextOf(peel(node.left));
    if (head !== null) return isSameSiteLiteral(head);
    return staysRelative(file, node.left, scope, callerSupplied);
  }
  if (!ts.isTemplateExpression(node)) return false;
  const head = node.head.text;
  if (!head.startsWith("/")) return false;
  if (head.length > 1) return isSameSiteLiteral(head);
  // The head is exactly "/", so the first interpolation decides: `/${x}` is
  // `//host/...` when x begins with a slash. It is safe when the caller did not
  // supply that part, or when it went through an encoder that escapes slashes.
  const first = node.templateSpans[0]?.expression;
  if (!first) return false;
  if (!callerSupplied(first)) return true;
  return escapesSeparators(file, first, scope);
}

/**
 * Did this value pass through an encoder that cannot emit a path separator?
 *
 * `encodeURIComponent` turns a slash into `%2F`, so its output can neither open a
 * new path segment nor start a protocol-relative reference. `encodeURI` does not,
 * and is deliberately not accepted.
 */
function escapesSeparators(file: ParsedFile, expression: ts.Node, scope: TaintScope, depth = 0): boolean {
  if (depth > 3) return false;
  const node = peel(resolveExpression(peel(expression), scope));
  if (!ts.isCallExpression(node)) return false;
  const tail = calleeTail(node);
  if (tail === "encodeURIComponent") return true;
  if (tail === "basename" || tail === "extname") return true;
  const helper = producingHelper(file, node, scope);
  if (!helper) return false;
  let encodes = false;
  walk(helper, (inner) => {
    if (ts.isCallExpression(inner) && calleeTail(inner) === "encodeURIComponent") encodes = true;
  });
  return encodes;
}

export const outboundRequestForgery: Rule = {
  id: "perimeter-ssrf",
  category: "server_side_request_forgery",
  describes: "caller-influenced destinations for server-side HTTP requests",
  run(context: RuleContext) {
    const reported = new Set<number>();
    for (const fn of handlersIn(context.file)) {
      const scope = scopeFor(context.file, fn);

      for (const call of collect(fn, ts.isCallExpression)) {
        if (!isOutboundRequest(context.file, call)) continue;
        const destination = outboundDestination(call);
        if (!destination) continue;
        if (isConstantString(destination)) continue;
        if (hasFixedOrigin(destination)) continue;
        if (resolvedOnFixedOrigin(context.file, destination, scope)) continue;

        const origin = taintOrigin(destination, scope);
        if (!origin) continue;

        const root = rootOf(destination);
        if (root && (scope.allowlisted.has(root) || scope.cleared.has(root))) continue;
        if (root && hostConstrained(context.file, fn, root, call)) continue;

        // The correct form is often a resolver: parse the URL, look the host up in
        // a table of the endpoints this feature is allowed to reach, return null
        // otherwise. Reading that helper is what keeps the rule off correct code.
        const helper = producingHelper(context.file, destination, scope);
        if (helper && (hostConstrained(context.file, helper, null) || helperFixesOrigin(context.file, helper))) continue;
        if (!helper && producedByUnreadableCall(context.file, destination, scope)) continue;

        if (reported.has(lineOf(context.file, call))) continue;
        reported.add(lineOf(context.file, call));

        const name = calleeName(call) || calleeTail(call);
        context.report({
          ruleId: "perimeter-ssrf",
          category: "server_side_request_forgery",
          title: `Server issues a request to a caller-influenced destination via ${name}`,
          severity: "high",
          verification: "strong_evidence",
          summary: `The destination given to ${name} is derived from ${origin}, and nothing between the read and the call restricts which host it may name — no allowlist of origins, no comparison of the parsed hostname against one, and no fixed scheme-and-host prefix. The caller therefore chooses what the server connects to.`,
          impact:
            "The attacker makes this server reach addresses they cannot reach themselves: internal services with no authentication of their own, the cloud instance metadata endpoint and the credentials it hands out, and anything else inside the network perimeter. Where the response body or its status and timing come back to the caller, it also becomes a scanner and a read primitive against those systems.",
          remediation:
            "Parse the destination, require an https scheme, and require its hostname to appear in an explicit allowlist before the request is issued — resolving the name and rejecting private, loopback, and link-local addresses if the allowlist has to be broad. Refuse redirects rather than following them, since a permitted host can redirect to a forbidden one, and do not return the fetched body to the caller verbatim.",
          verificationPlan:
            "Send a destination of `http://169.254.169.254/latest/meta-data/`, then a permitted host that redirects to it, and confirm both are refused before any outbound connection is made and that the response reveals nothing about which internal addresses answered.",
          taxonomy: ["CWE-918", "OWASP-A10"],
          location: locationOf(context, call),
          ...withRoute(context, call),
          evidence: [
            sourceEvidence(context, call, `${name} is called with a caller-influenced destination and no host allowlist.`),
            taintEvidence(origin, describeSink(call))
          ],
          reasoning: `Taint from ${origin} reaches the destination of ${name}; no membership guard, hostname comparison, constant origin prefix, or validating helper was found on its root binding.`
        });
      }
    }
  }
};

/* ------------------------------------------------------------------------- *
 * Cross-origin policy
 * ------------------------------------------------------------------------- */

const HEADER_SETTERS = new Set(["set", "setHeader", "header", "append", "put"]);
const ALLOW_ORIGIN = /^access-control-allow-origin$/i;
const ALLOW_CREDENTIALS = /^access-control-allow-credentials$/i;
const CORS_CONFIGURERS = /^(cors|fastifyCors|NextCors|corsMiddleware)$/;

/** Does this function allow credentials anywhere in it? */
function allowsCredentials(file: ParsedFile, region: ts.Node): boolean {
  let allows = false;
  walk(region, (node) => {
    if (allows) return;
    if (ts.isPropertyAssignment(node)) {
      const key = propertyKey(file, node);
      if (/^credentials$/.test(key) && node.initializer.kind === ts.SyntaxKind.TrueKeyword) allows = true;
      // A header map spells the same decision as a header name and a value, and a
      // runtime that returns its headers as an object literal never calls a setter
      // at all.
      if (ALLOW_CREDENTIALS.test(key)) {
        const text = literalTextOf(peel(node.initializer));
        if (text === null || text === "true") allows = true;
      }
    }
    if (!ts.isCallExpression(node)) return;
    const first = node.arguments[0];
    const header = first ? literalTextOf(first) : null;
    if (!header || !ALLOW_CREDENTIALS.test(header)) return;
    const value = node.arguments[1] ? literalTextOf(node.arguments[1]!) : null;
    if (value === null || value === "true") allows = true;
  });
  return allows;
}

/** The `origin` option of a CORS configuration call, when it has one. */
function corsOriginOption(call: ts.CallExpression): ts.Expression | undefined {
  const first = call.arguments[0] ? peel(call.arguments[0]!) : undefined;
  if (!first || !ts.isObjectLiteralExpression(first)) return undefined;
  for (const property of first.properties) {
    if (!ts.isPropertyAssignment(property)) continue;
    if (property.name.getText().replace(/["']/g, "") === "origin") return property.initializer;
  }
  return undefined;
}

/** The innermost function whose taint scope owns this node. */
function enclosingHandler(context: RuleContext, node: ts.Node): ts.Node {
  const handlers = handlersIn(context.file);
  let current: ts.Node | undefined = node;
  while (current) {
    if (handlers.includes(current)) return current;
    current = current.parent;
  }
  return context.file.source;
}

/** The name a function is declared under, however it is written. */
function declaredFunctionName(fn: ts.Node): string | null {
  if ((ts.isFunctionDeclaration(fn) || ts.isFunctionExpression(fn)) && fn.name) return fn.name.text;
  const parent = fn.parent;
  if (parent && ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) return parent.name.text;
  return null;
}

/**
 * What this file passes into one parameter of a locally declared function.
 *
 * The engine follows data inside a single function and says so. That is the right
 * scope almost everywhere, but a cross-origin decision is normally written once —
 * `corsHeaders(origin)` — and called from every route with
 * `request.headers.get("origin")`. Inside the helper the value is an ordinary
 * parameter, so reasoning within one function cannot see that it is the request's
 * own Origin, and the commonest spelling of reflected CORS is invisible. Reading
 * the call sites in the same file is a single, bounded step that connects them.
 */
function argumentOriginAtCallSites(context: RuleContext, fn: ts.Node, parameter: string): string | null {
  const parameters = (fn as ts.FunctionLikeDeclaration).parameters ?? [];
  const index = parameters.findIndex((entry) => ts.isIdentifier(entry.name) && entry.name.text === parameter);
  if (index < 0) return null;
  const name = declaredFunctionName(fn);
  if (!name) return null;

  const handlers = handlersIn(context.file);
  for (const call of collect(context.file.source, ts.isCallExpression)) {
    if (!ts.isIdentifier(call.expression) || call.expression.text !== name) continue;
    const argument = call.arguments[index];
    if (!argument) continue;
    let owner: ts.Node | undefined = call;
    while (owner && !handlers.includes(owner)) owner = owner.parent;
    if (!owner || owner === fn) continue;
    const origin = taintOrigin(argument, scopeFor(context.file, owner));
    if (origin) return origin;
  }
  return null;
}

/** Where an allowed-origin value came from, following one call into its decider. */
function reflectedOrigin(
  context: RuleContext,
  owner: ts.Node,
  scope: TaintScope,
  value: ts.Expression
): string | null {
  const direct = taintOrigin(value, scope);
  if (direct) return direct;
  const name = rootOf(value);
  if (!name || !parameterNames(owner).has(name)) return null;
  return argumentOriginAtCallSites(context, owner, name);
}

export const crossOriginPolicy: Rule = {
  id: "perimeter-cors",
  category: "insecure_cors_configuration",
  describes: "reflected, wildcarded, or unconditionally permissive cross-origin policy",
  run(context: RuleContext) {
    const reported = new Set<number>();
    reportReflectedHeaders(context, reported);
    reportHeaderMapOrigins(context, reported);
    reportCorsConfiguration(context, reported);
  }
};

/**
 * Cross-origin policy written as a header map rather than as a setter.
 *
 * `new Response(body, { headers })` and `Response.json(row, { headers })` are how
 * every web-platform runtime answers a request — an edge worker has no `res`
 * object to set a header on. The decision is identical and so is the defect, and
 * a rule that only understands `res.setHeader` and `cors()` middleware sees none
 * of it.
 */
function reportHeaderMapOrigins(context: RuleContext, reported: Set<number>): void {
  for (const entry of collect(context.file.source, ts.isPropertyAssignment)) {
    if (!ALLOW_ORIGIN.test(propertyKey(context.file, entry))) continue;

    const owner = enclosingHandler(context, entry);
    const scope = scopeFor(context.file, owner);
    const value = entry.initializer;
    const credentials = allowsCredentials(context.file, owner);
    const literal = literalTextOf(peel(value));

    if (literal === "*") {
      report(context, entry, "wildcard", credentials, reported);
      continue;
    }
    // A fixed origin is the correct answer and needs no further reasoning.
    if (literal !== null) continue;

    const origin = reflectedOrigin(context, owner, scope, value);
    if (!origin) continue;

    const root = rootOf(value);
    // A membership test whose failing branch stops the function is the correct
    // fix, and so is one that gates the branch the headers are written in: the
    // headers are simply not produced for an origin that is not on the list.
    if (root && (scope.allowlisted.has(root) || scope.cleared.has(root))) continue;
    const gated = gatingConditions(entry, owner).some(
      (condition) =>
        root !== null &&
        (testsMembershipOf(context.file, condition, root) ||
          originPredicateConstrains(context.file, condition, root))
    );
    if (gated) continue;

    report(context, entry, "reflected", credentials, reported, origin);
  }
}

/**
 * Does an `if` around a reflection call a local predicate that constrains the
 * origin to this application's own?
 *
 * The correct form of a credentialed CORS policy over customer subdomains is a
 * named predicate: parse the Origin, require https, and require the parsed
 * hostname either to equal the root domain or to end at a label boundary below
 * it. There is no fixed list to be a member of — the subdomains are per customer
 * — so the membership test the rule already understands is not available, and
 * without this the engine reports the one implementation that gets it right.
 *
 * The label boundary is the whole precision argument and is required, not
 * inferred: `hostname.endsWith("pulse.dev")` also accepts `notpulse.dev`, which
 * is the bug this shape exists to avoid. Only a suffix that begins with a dot
 * counts, alongside equality and membership in a constant table.
 */
function originPredicateConstrains(file: ParsedFile, condition: ts.Node, name: string): boolean {
  let constrained = false;
  walk(condition, (node) => {
    if (constrained) return;
    if (!ts.isCallExpression(node) || !ts.isIdentifier(node.expression)) return;
    if (!node.arguments.some((argument) => rootOf(argument) === name)) return;

    const declaration = localFunction(file, node.expression.text);
    if (!declaration) return;

    const parameter = ts.isFunctionLike(declaration) ? declaration.parameters[0] : undefined;
    const subject = parameter && ts.isIdentifier(parameter.name) ? parameter.name.text : null;
    if (!subject) return;

    let parses = false;
    let anchored = false;
    walk(declaration, (inner) => {
      if (ts.isNewExpression(inner) && expressionName(inner.expression) === "URL") parses = true;

      if (ts.isCallExpression(inner) && calleeTail(inner) === "endsWith") {
        const argument = inner.arguments[0];
        if (!argument) return;
        const suffix = ts.isStringLiteralLike(argument)
          ? argument.text
          : ts.isTemplateExpression(argument)
            ? argument.head.text
            : null;
        if (suffix !== null && suffix.startsWith(".")) anchored = true;
      }

      if (ts.isBinaryExpression(inner)) {
        const isEquality =
          inner.operatorToken.kind === ts.SyntaxKind.EqualsEqualsEqualsToken ||
          inner.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsEqualsToken;
        if (!isEquality) return;
        for (const side of [inner.left, inner.right]) {
          if (ts.isPropertyAccessExpression(side) && /^(origin|host|hostname)$/.test(side.name.text)) anchored = true;
        }
      }
    });

    // A predicate that reaches its own decision through the membership test the
    // rule already reads is equally correct and does not need to parse anything.
    if (testsMembershipOf(file, declaration, subject)) constrained = true;
    if (parses && anchored) constrained = true;
  });
  return constrained;
}

function reportReflectedHeaders(context: RuleContext, reported: Set<number>): void {
  for (const fn of handlersIn(context.file)) {
    const scope = scopeFor(context.file, fn);

    for (const call of collect(fn, ts.isCallExpression)) {
      if (!HEADER_SETTERS.has(calleeTail(call))) continue;
      const first = call.arguments[0];
      const header = first ? literalTextOf(peel(first)) : null;
      if (!header || !ALLOW_ORIGIN.test(header)) continue;
      const value = call.arguments[1];
      if (!value) continue;

      const literal = literalTextOf(peel(value));
      const credentials = allowsCredentials(context.file, fn);
      const origin = reflectedOrigin(context, fn, scope, value);
      const root = rootOf(value);

      let reflected = false;
      if (literal === "*") {
        // A wildcard with credentials is rejected by browsers, so on its own it is
        // a data-exposure decision rather than a session-riding one.
        report(context, call, "wildcard", credentials, reported);
        continue;
      }
      if (origin) reflected = true;
      if (!reflected) continue;

      // An allowlist test that gates the reflection is the correct fix, and it
      // gates rather than terminates: the headers are simply not set for an
      // origin that is not on the list.
      const gated = gatingConditions(call, fn).some(
        (condition) =>
          root !== null &&
          (testsMembershipOf(context.file, condition, root) ||
            originPredicateConstrains(context.file, condition, root))
      );
      if (gated) continue;
      if (root && (scope.allowlisted.has(root) || scope.cleared.has(root))) continue;

      report(context, call, "reflected", credentials, reported, origin ?? undefined);
    }
  }
}

function reportCorsConfiguration(context: RuleContext, reported: Set<number>): void {
  for (const call of collect(context.file.source, ts.isCallExpression)) {
    const name = calleeName(call);
    const tail = calleeTail(call);
    if (!CORS_CONFIGURERS.test(name) && !CORS_CONFIGURERS.test(tail)) continue;

    const option = corsOriginOption(call);
    const credentials = allowsCredentials(context.file, call);

    if (!option) continue;

    if (option.kind === ts.SyntaxKind.TrueKeyword) {
      report(context, call, "permissive", credentials, reported);
      continue;
    }
    const literal = literalTextOf(peel(option));
    if (literal === "*") {
      report(context, call, "wildcard", credentials, reported);
      continue;
    }
    if (ts.isArrayLiteralExpression(peel(option)) || isConstantTable(context.file, peel(option))) continue;

    if (ts.isArrowFunction(option) || ts.isFunctionExpression(option)) {
      const parameter = option.parameters[0];
      const subject = parameter && ts.isIdentifier(parameter.name) ? parameter.name.text : null;
      // A callback that decides is fine; a callback that hands the request's own
      // origin straight back is reflection with extra steps.
      if (subject && testsMembershipOf(context.file, option, subject)) continue;
      let echoes = false;
      walk(option, (node) => {
        if (ts.isIdentifier(node) && subject && node.text === subject && node.parent !== parameter) echoes = true;
        if (ts.isStringLiteralLike(node) && node.text === "*") echoes = true;
      });
      if (echoes) report(context, call, "reflected", credentials, reported);
    }
  }
}

type CorsShape = "reflected" | "wildcard" | "permissive";

function report(
  context: RuleContext,
  node: ts.Node,
  shape: CorsShape,
  credentials: boolean,
  reported: Set<number>,
  origin?: string
): void {
  if (reported.has(lineOf(context.file, node))) return;
  reported.add(lineOf(context.file, node));

  const titles: Record<CorsShape, string> = {
    reflected: credentials
      ? "The request's own Origin is echoed back as the allowed origin, together with credentials"
      : "The request's own Origin is echoed back as the allowed origin",
    wildcard: credentials
      ? "Cross-origin policy wildcards the origin while also allowing credentials"
      : "Cross-origin policy allows any origin to read responses",
    permissive: credentials
      ? "Cross-origin policy accepts every origin (`origin: true`) while also allowing credentials"
      : "Cross-origin policy accepts every origin (`origin: true`)"
  };

  const summaries: Record<CorsShape, string> = {
    reflected: `The value sent in Access-Control-Allow-Origin is the origin the request arrived with${origin ? `, read from ${origin}` : ""}, and no membership test decides whether that origin is one this application serves. Reflecting the header is functionally an allowlist of every site on the internet.${credentials ? " Credentials are allowed alongside it, so the browser attaches the victim's cookies to those cross-origin requests and lets the calling page read the answers." : ""}`,
    wildcard: `The policy names a wildcard as the allowed origin, so any site may read responses from this API.${credentials ? " It also allows credentials; browsers refuse that exact combination, so the practical effect is an inconsistent policy that gets \"fixed\" by reflecting the request's origin instead — which is the vulnerable form." : ""}`,
    permissive: `The cross-origin option is set to accept whatever origin asks, which the middleware implements by echoing it back.${credentials ? " Credentials are allowed alongside it, so a page on any origin can act as the signed-in victim against this API and read the response." : ""}`
  };

  context.report({
    ruleId: "perimeter-cors",
    category: "insecure_cors_configuration",
    title: titles[shape],
    severity: credentials ? "high" : "medium",
    verification: "strong_evidence",
    summary: summaries[shape],
    impact: credentials
      ? "Any website a signed-in user visits can make authenticated requests to this API from their browser and read the responses. That is cross-site request forgery with the reply readable: account data can be exfiltrated and state-changing endpoints can be driven, from an origin the application has never heard of."
      : "Data this API returns is readable by script on any origin, so anything behind it that is not separately authorised leaks to any page a user visits.",
    remediation:
      "Decide the allowed origin from a fixed list of the front ends this API actually serves, compare the request's Origin against that list, and send the header only on a match. Add `Vary: Origin` so a cache cannot serve one origin's response to another, and never pair a wildcard or an unconditioned reflection with credentials. Where the widget genuinely runs on customer domains, register those domains per tenant and treat the list as configuration, not as request data.",
    verificationPlan:
      "Send a request with `Origin: https://example.test` and confirm the response carries no Access-Control-Allow-Origin for it; repeat with credentials to confirm the browser is not permitted to read the body.",
    taxonomy: ["CWE-942", "CWE-346", "OWASP-A05"],
    location: locationOf(context, node),
    ...withRoute(context, node),
    evidence: [sourceEvidence(context, node, "Cross-origin policy.")],
    reasoning:
      shape === "reflected"
        ? `The allowed-origin value derives from the request's Origin and no membership test against a fixed set gates it${credentials ? "; credentials are allowed in the same configuration" : ""}.`
        : `The allowed-origin value is ${shape === "wildcard" ? "a wildcard" : "unconditionally permissive"}${credentials ? " and credentials are allowed alongside it" : ""}.`
  });
}

/* ------------------------------------------------------------------------- *
 * Missing rate limit on credential routes
 * ------------------------------------------------------------------------- */

/** Expressions that verify a secret the caller presented. */
const CREDENTIAL_VERIFICATION =
  /bcrypt\s*\.\s*(compare|compareSync)|argon2\s*\.\s*verify|scrypt|pbkdf2|verifyPassword|comparePassword|checkPassword|timingSafeEqual|verifyTotp|verifyOtp|verifyCode|codeHash|tokenHash|passwordHash|password_hash|signAccessToken|createSession|issueToken/i;

/** Route paths whose name says they exchange a credential for a session. */
const CREDENTIAL_PATH =
  /(login|log-in|signin|sign-in|session|token|password|passwd|credential|grant|otp|mfa|2fa|totp|challenge|verify|reset|forgot|authenticate)/i;

/** Anything that shows this module knows about rate limiting. */
const RATE_LIMIT_EXPRESSION = /rate.?limit|ratelimit|throttl|slow.?down|bottleneck|leaky.?bucket|too.?many.?(requests|attempts)|429/i;

function fileMentionsRateLimiting(file: ParsedFile): boolean {
  if (RATE_LIMIT_EXPRESSION.test(importedModules(file).join(" "))) return true;
  let mentions = false;
  walk(file.source, (node) => {
    if (mentions) return;
    if (ts.isPropertyAssignment(node) && RATE_LIMIT_EXPRESSION.test(node.name.getText(file.source))) mentions = true;
    if (ts.isCallExpression(node) && RATE_LIMIT_EXPRESSION.test(calleeName(node))) mentions = true;
    if (ts.isIdentifier(node) && RATE_LIMIT_EXPRESSION.test(node.text)) mentions = true;
  });
  return mentions;
}

function importedModules(file: ParsedFile): string[] {
  const modules: string[] = [];
  for (const statement of file.source.statements) {
    if (ts.isImportDeclaration(statement) && ts.isStringLiteralLike(statement.moduleSpecifier)) {
      modules.push(statement.moduleSpecifier.text);
    }
  }
  walk(file.source, (node) => {
    if (!ts.isCallExpression(node) || calleeName(node) !== "require") return;
    const first = node.arguments[0];
    const text = first ? literalTextOf(first) : null;
    if (text) modules.push(text);
  });
  return modules;
}

/** Does this registration or handler carry a rate limit of its own? */
/**
 * Does this identifier hold a limiter built elsewhere in the file?
 *
 *     const loginLimiter = rateLimit({ windowMs: 900000, max: 10 });
 *     router.post("/session", loginLimiter, handler);
 *
 * That is the documented Express pattern and the reason to use it is to share one
 * limiter across several routes, so it is what a careful application looks like.
 * Reading only the registration sees a bare identifier, concludes no limiter, and
 * reports the route that is actually protected — quietly, as a candidate, on the
 * commonest correct shape there is.
 */
function resolvesToRateLimiter(file: ParsedFile, node: ts.Node): boolean {
  if (!ts.isIdentifier(node)) return false;
  let found = false;
  walk(file.source, (candidate) => {
    if (found) return;
    if (!ts.isVariableDeclaration(candidate)) return;
    if (!ts.isIdentifier(candidate.name) || candidate.name.text !== node.text) return;
    const initializer = candidate.initializer;
    if (!initializer) return;
    if (ts.isCallExpression(initializer) && RATE_LIMIT_EXPRESSION.test(calleeName(initializer))) found = true;
    // `const limiter = { windowMs, max }` handed to a framework that takes options.
    if (ts.isObjectLiteralExpression(initializer) && RATE_LIMIT_EXPRESSION.test(initializer.getText(file.source))) {
      found = true;
    }
  });
  return found;
}

function hasOwnRateLimit(file: ParsedFile, region: ts.Node): boolean {
  let limited = false;
  walk(region, (node) => {
    if (limited) return;
    if (ts.isPropertyAssignment(node) && /rate.?limit|throttl/i.test(node.name.getText(file.source))) limited = true;
    if (ts.isCallExpression(node) && RATE_LIMIT_EXPRESSION.test(calleeName(node))) limited = true;
    if (ts.isNumericLiteral(node) && node.text === "429") limited = true;
    if (resolvesToRateLimiter(file, node)) limited = true;
  });
  return limited;
}

export const credentialRouteRateLimit: Rule = {
  id: "perimeter-credential-rate-limit",
  category: "missing_rate_limit_on_credentials",
  describes: "credential-checking routes with no rate limit in a module that rate-limits others",
  run(context: RuleContext) {
    for (const call of collect(context.file.source, ts.isCallExpression)) {
      if (!ts.isPropertyAccessExpression(call.expression)) continue;
      const method = call.expression.name.text.toLowerCase();
      if (!HTTP_METHOD_CALLS.has(method) || method === "use") continue;
      const first = call.arguments[0];
      if (!first) continue;
      const path = literalTextOf(first);
      if (!path || !path.startsWith("/")) continue;

      const handler = call.arguments.find(
        (argument) => ts.isArrowFunction(argument) || ts.isFunctionExpression(argument)
      );
      if (!handler) continue;

      const handlerText = handler.getText(context.file.source);
      const verifiesCredential = CREDENTIAL_VERIFICATION.test(handlerText);
      if (!verifiesCredential) continue;
      if (!CREDENTIAL_PATH.test(path)) continue;

      // The whole registration is the region: a limiter can sit in the options
      // object, in a middleware argument, or inside the handler body.
      if (hasOwnRateLimit(context.file, call)) continue;

      /*
       * With a limited sibling this is a gap; without one it is a question.
       *
       * The rule used to return outright when the module mentioned no rate limiting at
       * all, because the contrast is what distinguishes an application whose limiter
       * lives in a gateway from one that has none — and guessing would report every
       * correctly written sign-in handler.
       *
       * That reasoning is sound and its consequence was never written down: **an
       * application with no rate limiting anywhere got no finding at all.** The one
       * shape most likely to be genuinely unprotected was the one shape guaranteed
       * silence. Reporting it as `needs_review` says what is actually known — no
       * limiter is visible in this module, and the engine cannot see a gateway — which
       * is a question a reader can answer in seconds and dismiss.
       *
       * This became shippable once `benchmark/score-corpus.mjs` stopped counting an
       * unsettled candidate as a false claim. Before that, emitting it would have read
       * as a precision collapse on every corpus.
       */
      const siblings = limitedSiblings(context.file, call);
      const contrasted = siblings.length > 0;
      const moduleLimitsSomething = fileMentionsRateLimiting(context.file);

      if (!contrasted) {
        context.report({
          ruleId: "perimeter-credential-rate-limit",
          category: "missing_rate_limit_on_credentials",
          title: `${method.toUpperCase()} ${path} verifies a credential and no rate limit is visible`,
          severity: "medium",
          verification: "needs_review",
          summary:
            `This route checks a secret the caller supplied, so every request to it is a guess that either succeeds or does not. No rate limit appears in its options, as middleware, or inside the handler${moduleLimitsSomething ? ", and no other route in this module declares one either" : ", and nothing in this module mentions rate limiting at all"}. ` +
            "A limiter enforced by a gateway, a proxy, or a platform edge would not be visible to a static reading, so this is reported as a question rather than a defect: confirm where yours runs.",
          impact:
            "If nothing throttles this endpoint, an attacker can test passwords, one-time codes, or tokens as fast as the network allows. A six-digit code is exhausted in minutes and a credential-stuffing list runs unimpeded. If a limiter does run in front of this service, there is nothing to fix here.",
          remediation:
            "Confirm whether a limiter covers this route. If one does, record where it runs so the next reader does not have to ask. If none does, add one keyed on both the client address and the account being addressed, count failures rather than requests, keep the counter server-side, and return the same response and timing whether or not the account exists.",
          verificationPlan:
            "Send twenty failed attempts in quick succession from one address against one account. A 429, or a growing delay, means a limiter covers this route and this finding can be dismissed. Twenty clean rejections at full speed means it does not.",
          taxonomy: ["CWE-307", "CWE-799", "OWASP-A07"],
          location: locationOf(context, call),
          ...withRoute(context, call),
          evidence: [
            sourceEvidence(context, call, "Credential-verifying route registered with no visible rate limit."),
            {
              kind: "source",
              description: moduleLimitsSomething
                ? "Rate limiting is mentioned in this module but no route declares one, so the convention cannot be read from the code."
                : "Nothing in this module mentions rate limiting, so whether a limiter exists cannot be determined from this file."
            }
          ],
          reasoning: `Handler for ${method.toUpperCase()} ${path} contains a credential-verification expression and no rate-limit option, middleware, or in-handler limiter appears in its registration. No sibling route establishes the module's convention, so the absence is unsettled rather than established.`
        });
        continue;
      }

      context.report({
        ruleId: "perimeter-credential-rate-limit",
        category: "missing_rate_limit_on_credentials",
        title: `${method.toUpperCase()} ${path} verifies a credential with no rate limit, while neighbouring routes have one`,
        severity: "medium",
        verification: "strong_evidence",
        summary: `This route checks a secret the caller supplied, so every request to it is a guess that either succeeds or does not. It carries no rate limit: not in its own options, not as middleware, and not inside the handler. The other credential routes in this module — ${siblings.join(", ")} — each declare one, so the module's convention is a per-route limit and this route is the one that was missed.`,
        impact:
          "An attacker can test passwords, one-time codes, or tokens against this endpoint as fast as the network allows. A six-digit code is exhausted in minutes and a credential-stuffing list runs unimpeded, so the strength of the password policy stops being what decides whether accounts fall.",
        remediation:
          "Apply the same limiter the neighbouring routes use, keyed on both the client address and the account being addressed so one attacker cannot hide behind a rotating address and cannot lock a victim out by targeting them. Count failures rather than requests, keep the counter server-side, and return the same response and the same timing whether or not the account exists.",
        verificationPlan:
          "Send twenty failed attempts in quick succession from one address against one account, and again across many addresses against one account; confirm both are throttled with 429 and that the successful-attempt path is unaffected for a different account.",
        taxonomy: ["CWE-307", "CWE-799", "OWASP-A07"],
        location: locationOf(context, call),
        ...withRoute(context, call),
        evidence: [
          sourceEvidence(context, call, "Credential-verifying route registered with no rate limit."),
          {
            kind: "source",
            description: `Rate limiting is configured in this module and applied to ${siblings.join(", ")}, which is what makes the absence here a gap rather than an architectural choice.`
          }
        ],
        reasoning: `Handler for ${method.toUpperCase()} ${path} contains a credential-verification expression; no rate-limit option, middleware, or in-handler limiter appears in its registration, while ${siblings.length} sibling route(s) in the same module declare one.`
      });
    }
  }
};

/** Routes in the same file that do declare a rate limit. */
function limitedSiblings(file: ParsedFile, subject: ts.CallExpression): string[] {
  const siblings: string[] = [];
  for (const call of collect(file.source, ts.isCallExpression)) {
    if (call === subject) continue;
    if (!ts.isPropertyAccessExpression(call.expression)) continue;
    const method = call.expression.name.text.toLowerCase();
    if (!HTTP_METHOD_CALLS.has(method)) continue;
    const first = call.arguments[0];
    const path = first ? literalTextOf(first) : null;
    if (!path || !path.startsWith("/")) continue;
    if (!hasOwnRateLimit(file, call)) continue;
    siblings.push(`${method.toUpperCase()} ${path}`);
  }
  return [...new Set(siblings)];
}

/* ------------------------------------------------------------------------- *
 * Unbounded resource consumption
 * ------------------------------------------------------------------------- */

const LIMIT_PROPERTIES = new Set([
  "take",
  "limit",
  "first",
  "perPage",
  "per_page",
  "pageSize",
  "page_size",
  "maxResults",
  "max_results",
  "top"
]);

const LIMIT_METHODS = new Set(["limit", "take", "first", "maxResults"]);

/** Calls whose options object decides how many records come back. */
const LIST_QUERIES = new Set([
  "findMany",
  "findAll",
  "find",
  "aggregate",
  "scan",
  "paginate",
  "search",
  "list",
  "query",
  "select",
  "getAll",
  "toArray"
]);

/** Receivers that plausibly are a query builder rather than an unrelated object. */
const QUERY_RECEIVER = /\b(db|database|prisma|knex|sequelize|drizzle|mongo|collection|table|model|repo|repository|query|builder|select|from|where|orderBy|find\w*)\b/i;

/**
 * Is this object literal the options of a call that returns a list?
 *
 * `limit`, `take`, and `first` are ordinary words. A quota object with a
 * `limit` field, a body-parser configured with `{ limit: "1mb" }`, and a
 * rate-limit descriptor all use them, and none of them is a page size — so the
 * property only counts when the object is being handed to something that reads
 * records.
 */
function isListQueryOptions(property: ts.Node): boolean {
  let current: ts.Node | undefined = property.parent;
  let depth = 0;
  while (current && depth < 4) {
    if (ts.isCallExpression(current)) {
      return LIST_QUERIES.has(calleeTail(current));
    }
    if (!ts.isObjectLiteralExpression(current) && !ts.isPropertyAssignment(current) && !ts.isSpreadAssignment(current)) {
      return false;
    }
    current = current.parent;
    depth += 1;
  }
  return false;
}

/** Parameter names that carry the caller's own arguments into a resolver. */
const CLIENT_ARGUMENT_NAMES = new Set(["input", "args", "arguments", "params", "query", "body", "variables"]);

/** Names a resolver gives its first, server-supplied parameter. */
const RESOLVER_PARENT = /^_?(parent|root|obj|source)$/;

/** Bindings that hold the caller's arguments in this function. */
function clientArgumentBindings(fn: ts.Node): Set<string> {
  const names = new Set<string>();
  const parameters = (fn as ts.FunctionLikeDeclaration).parameters;
  if (!parameters) return names;

  parameters.forEach((parameter, index) => {
    const isResolverArgs = index === 1 && parameters.length >= 3 && isResolverParent(parameters[0]);
    if (ts.isIdentifier(parameter.name)) {
      if (CLIENT_ARGUMENT_NAMES.has(parameter.name.text) || isResolverArgs) names.add(parameter.name.text);
      return;
    }
    if (!ts.isObjectBindingPattern(parameter.name)) return;
    for (const element of parameter.name.elements) {
      const source =
        element.propertyName && ts.isIdentifier(element.propertyName)
          ? element.propertyName.text
          : ts.isIdentifier(element.name)
            ? element.name.text
            : null;
      if (!isResolverArgs && (!source || !CLIENT_ARGUMENT_NAMES.has(source))) continue;
      for (const name of boundNames(element.name)) names.add(name);
    }
  });
  return names;
}

function isResolverParent(parameter: ts.ParameterDeclaration | undefined): boolean {
  if (!parameter || !ts.isIdentifier(parameter.name)) return false;
  return RESOLVER_PARENT.test(parameter.name.text);
}

/** A ceiling anywhere in this expression, or in the helper that produced it. */
function isClamped(file: ParsedFile, expression: ts.Node, scope: TaintScope, depth = 0): boolean {
  if (depth > 4) return true;
  const node = peel(expression);

  if (ts.isNumericLiteral(node) || ts.isStringLiteralLike(node)) return true;
  if (ts.isPrefixUnaryExpression(node) && ts.isNumericLiteral(node.operand)) return true;

  if (ts.isCallExpression(node)) {
    if (calleeName(node) === "Math.min") return true;
    const helper = producingHelper(file, node, scope);
    if (helper && (clampsSomewhere(file, helper) || returnsOnlyFixedValues(file, helper))) return true;
  }

  if (ts.isConditionalExpression(node)) {
    return isClamped(file, node.whenTrue, scope, depth + 1) && isClamped(file, node.whenFalse, scope, depth + 1);
  }

  if (ts.isIdentifier(node)) {
    if (schemaBoundsField(file, node.text)) return true;
    const initializer = scope.initializers.get(node.text) ?? moduleConstant(file, node.text);
    if (initializer) return isClamped(file, initializer, scope, depth + 1);
    return false;
  }

  if (ts.isPropertyAccessExpression(node)) {
    // `input.limit` where the procedure's schema declares limit with a maximum.
    if (schemaBoundsField(file, node.name.text)) return true;
    return false;
  }

  return false;
}

function clampsSomewhere(file: ParsedFile, region: ts.Node): boolean {
  let clamps = false;
  walk(region, (node) => {
    if (clamps) return;
    if (ts.isCallExpression(node) && calleeName(node) === "Math.min") clamps = true;
    if (ts.isBinaryExpression(node)) {
      const kind = node.operatorToken.kind;
      if (kind === ts.SyntaxKind.GreaterThanToken || kind === ts.SyntaxKind.GreaterThanEqualsToken) {
        if (ts.isNumericLiteral(peel(node.right)) || /max/i.test(node.right.getText(file.source))) clamps = true;
      }
    }
  });
  return clamps;
}

/** A validation schema in this file that puts a maximum on the named field. */
function schemaBoundsField(file: ParsedFile, field: string): boolean {
  let bounded = false;
  walk(file.source, (node) => {
    if (bounded) return;
    if (!ts.isPropertyAssignment(node)) return;
    if (node.name.getText(file.source).replace(/["']/g, "") !== field) return;
    const text = node.initializer.getText(file.source);
    if (/\.max\s*\(|\bmaximum\b|\bmaxItems\b/.test(text)) bounded = true;
  });
  return bounded;
}

function moduleConstant(file: ParsedFile, name: string): ts.Expression | undefined {
  for (const statement of file.source.statements) {
    if (!ts.isVariableStatement(statement)) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (ts.isIdentifier(declaration.name) && declaration.name.text === name && declaration.initializer) {
        return declaration.initializer;
      }
    }
  }
  return undefined;
}

interface LimitSite {
  node: ts.Node;
  expression: ts.Expression;
  label: string;
}

/** Every place this function decides how many rows to return. */
function limitSites(file: ParsedFile, fn: ts.Node): LimitSite[] {
  const sites: LimitSite[] = [];
  walk(fn, (node) => {
    if (ts.isPropertyAssignment(node)) {
      const name = node.name.getText(file.source).replace(/["']/g, "");
      if (!LIMIT_PROPERTIES.has(name)) return;
      if (!isListQueryOptions(node)) return;
      sites.push({ node, expression: node.initializer, label: name });
      return;
    }
    if (ts.isCallExpression(node) && LIMIT_METHODS.has(calleeTail(node)) && ts.isPropertyAccessExpression(node.expression)) {
      if (!QUERY_RECEIVER.test(node.expression.expression.getText(file.source))) return;
      const argument = node.arguments[0];
      if (argument) sites.push({ node, expression: argument, label: `${calleeTail(node)}()` });
      return;
    }
    // `... ORDER BY created_at DESC LIMIT ${pageSize}` in a tagged or plain template.
    if (ts.isTemplateExpression(node)) {
      let previous = node.head.text;
      for (const span of node.templateSpans) {
        if (/\blimit\s+$/i.test(previous)) sites.push({ node: span, expression: span.expression, label: "SQL LIMIT" });
        previous = span.literal.text;
      }
    }
  });
  return sites;
}

/** Lists in this file that come back with no ceiling at all. */
function unboundedListCalls(file: ParsedFile, fn: ts.Node): string[] {
  const calls: string[] = [];
  walk(fn, (node) => {
    if (!ts.isCallExpression(node)) return;
    const tail = calleeTail(node);
    if (tail !== "findMany" && tail !== "findAll") return;
    const first = node.arguments[0] ? peel(node.arguments[0]!) : undefined;
    if (!first || !ts.isObjectLiteralExpression(first)) return;
    const bounded = first.properties.some(
      (property) =>
        ts.isPropertyAssignment(property) &&
        LIMIT_PROPERTIES.has(property.name.getText(file.source).replace(/["']/g, ""))
    );
    if (!bounded) calls.push(`${calleeName(node)}() at line ${lineOf(file, node)}`);
  });
  return [...new Set(calls)];
}

export const unboundedResultSet: Rule = {
  id: "perimeter-unbounded-results",
  category: "unbounded_resource_consumption",
  describes: "a caller-chosen page size reaching a query with no ceiling",
  run(context: RuleContext) {
    const reportedFunctions = new Set<ts.Node>();
    const handlers = handlersIn(context.file);

    for (const fn of handlers) {
      if (fn === context.file.source) continue;
      if (reportedFunctions.has(fn)) continue;
      const scope = scopeFor(context.file, fn);
      const clientArguments = clientArgumentBindings(fn);

      for (const site of limitSites(context.file, fn)) {
        if (isClamped(context.file, site.expression, scope)) continue;

        const root = rootOf(site.expression);
        const tainted = taintOrigin(site.expression, scope);
        const fromClient = tainted ?? (root && clientArguments.has(root) ? `the \`${root}\` argument of this request` : null);
        if (!fromClient) continue;

        // Only report the outermost function that owns this site, so a nested
        // arrow inside a resolver does not produce a second copy of the finding.
        let owner: ts.Node | undefined = site.node;
        while (owner && !handlers.includes(owner)) owner = owner.parent;
        if (owner && reportedFunctions.has(owner)) continue;
        reportedFunctions.add(fn);

        const siblings = unboundedListCalls(context.file, context.file.source);
        const expressionText = site.expression.getText(context.file.source);

        context.report({
          ruleId: "perimeter-unbounded-results",
          category: "unbounded_resource_consumption",
          title: `The number of records returned is chosen by the caller (${site.label}: ${expressionText}) with no ceiling`,
          severity: "medium",
          verification: "needs_review",
          summary: `\`${expressionText}\` comes from ${fromClient} and is used directly as ${site.label}. There is no maximum: a request naming a page size of a million asks the database for a million rows, serialises them, and holds them in memory while it does. A default value is not a ceiling — it applies only when the caller declines to choose.${siblings.length > 0 ? ` The same surface also resolves ${siblings.length} list(s) with no limit at all, so the cost of one request is not bounded at any level.` : ""}`,
          impact:
            "One cheap request turns into an expensive query, a large serialisation, and a large response. Repeated, it exhausts database connections, heap, and egress for everyone else — a denial of service that needs no privilege and leaves a request log indistinguishable from ordinary paging. Where the list is nested, the cost multiplies with the depth the caller asks for.",
          remediation:
            "Clamp the page size to a maximum the query can serve — validate it as a positive integer and take the minimum of it and a constant — and apply the same ceiling to every nested list. For a GraphQL surface add depth and complexity limits at the server so a query cannot compose bounded resolvers into an unbounded request.",
          verificationPlan:
            "Ask for a page size far above the intended maximum and confirm the response carries no more than the ceiling; then time the request against a normal one to confirm the server did not do the larger amount of work before truncating.",
          taxonomy: ["CWE-770", "CWE-400", "OWASP-A04"],
          location: locationOf(context, site.node),
          ...withRoute(context, site.node),
          evidence: [
            sourceEvidence(context, site.node, `${site.label} is set from a caller-supplied value with no maximum applied.`),
            ...(siblings.length > 0
              ? [
                  {
                    kind: "source" as const,
                    description: `Lists resolved with no limit at all in this module: ${siblings.join("; ")}.`
                  }
                ]
              : [])
          ],
          reasoning: `${site.label} is set from \`${expressionText}\`, which derives from ${fromClient}; no Math.min, comparison ceiling, schema maximum, or clamping helper was found in its provenance. Whether the reachable volume matters is a judgement about this data, which is why this is reported for review rather than as settled.`
        });
        break;
      }
    }
  }
};
