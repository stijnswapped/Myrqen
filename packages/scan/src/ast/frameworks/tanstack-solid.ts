import ts from "typescript";
import {
  allCalls,
  functionOf,
  importsFrom,
  joinRoute,
  type EntryPoint,
  type FrameworkAdapter,
  type TaintSeed
} from "../entrypoints.js";
import { calleeTail, collect, literalTextOf } from "../helpers.js";
import { lineOf, type ParsedFile } from "../parse.js";

/* ------------------------------------------------------------------------- *
 * TanStack Start and SolidStart server functions
 *
 * This family exists to make a network call look like a local one, and it
 * succeeds well enough to fool a reader as thoroughly as it fools a scanner.
 * `createServerFn().handler(async ({ data }) => …)` and an `async function` under
 * a `"use server"` directive are compiled into HTTP endpoints anybody can address
 * — the compiler leaves a stub behind on the client and moves the body to the
 * server — but nothing at the call site says so. There is no route literal, no
 * `req`, no `res`, and no registration call for route discovery to find, so a
 * file full of caller-driven database writes reads as ordinary application code:
 * no entry point, therefore no request parameter, therefore no taint, therefore
 * silence from every data-flow rule in the engine.
 *
 * The address and the input both have to be recovered here, and they come from
 * different places. The address is the *name* the function is bound to, because
 * that is what the client imports and what a reader will search for; the wire
 * address is an opaque generated id that appears nowhere in the source and would
 * mean nothing in a report. The input is the argument, and which part of the
 * argument bag the caller chose differs per framework: a TanStack handler is
 * handed `{ data, context }` where only `data` came from the caller and `context`
 * was assembled by middleware, while a SolidStart server function is handed the
 * caller's arguments and nothing else.
 *
 * The `"use server"` directive is the shape most easily missed, because it is not
 * a call at all. It appears either as the first statement of a module — every
 * export of which is then an endpoint — or as the first statement of one function
 * body, which turns that single function into an endpoint while the module around
 * it stays ordinary client code. Both are checked, since either alone leaves half
 * the surface invisible.
 * ------------------------------------------------------------------------- */

/**
 * The packages that settle which framework a file belongs to.
 *
 * `@tanstack/start` was the package name before the framework-specific split, so
 * both it and `@tanstack/react-start`, `@tanstack/solid-start` and their siblings
 * have to match, along with the deep entry points (`/server`, `/client`) real
 * imports use.
 */
const TANSTACK_MODULES = /^@tanstack\/(?:[a-z]+-)?start(?:-[a-z0-9-]+)?(?:\/|$)/;

/** SolidStart's own package, its router, and Solid itself. */
const SOLID_MODULES = /^@solidjs\/(?:router|start)(?:\/|$)|^solid-js(?:\/|$)/;

const SERVER_DIRECTIVE = "use server";

const SOURCE_EXTENSION = /\.[cm]?[jt]sx?$/;

/** The builders a TanStack server route is declared with, old name and new. */
const TANSTACK_ROUTE_FACTORIES = new Set(["createServerFileRoute", "createServerRoute", "createAPIFileRoute"]);

/** The `@solidjs/router` factories that publish a function under a name. */
const SOLID_RPC_FACTORIES = new Set(["action", "query", "cache"]);

const HTTP_VERBS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]);

/**
 * The address a server function gets when it is bound to nothing a reader can
 * name — an inline default export, or a handler passed straight to a helper.
 * The seeds are the half the data-flow rules cannot do without, so the entry
 * point is still emitted; only the label degrades.
 */
const UNNAMED = "server-function";

/* ------------------------------------------------------------------ *
 * Directives
 * ------------------------------------------------------------------ */

/**
 * Does this statement list open with a `"use server"` directive?
 *
 * A directive prologue is the run of bare string-literal statements a body
 * starts with, so `"use strict"; "use server";` is as much a server module as
 * the directive on its own — the runtime reads the whole prologue, and stopping
 * at the first statement would miss a file that a bundler or a linter reordered.
 * `ts.isStringLiteral` rather than the `Like` form on purpose: a template literal
 * is an expression the runtime evaluates, never a directive it obeys.
 */
function opensWithServerDirective(statements: ts.NodeArray<ts.Statement> | undefined): boolean {
  if (!statements) return false;
  for (const statement of statements) {
    if (!ts.isExpressionStatement(statement) || !ts.isStringLiteral(statement.expression)) return false;
    if (statement.expression.text === SERVER_DIRECTIVE) return true;
  }
  return false;
}

/** Is the whole module compiled to server functions? */
function isServerModule(file: ParsedFile): boolean {
  return opensWithServerDirective(file.source.statements);
}

/** Is this one function body compiled to a server function of its own? */
function hasServerDirective(fn: ts.Node | undefined): boolean {
  const body = (fn as ts.FunctionLikeDeclaration | undefined)?.body;
  if (!body || !ts.isBlock(body)) return false;
  return opensWithServerDirective(body.statements);
}

/* ------------------------------------------------------------------ *
 * Names, functions and addresses
 * ------------------------------------------------------------------ */

/** Every local binding a parameter introduces, destructuring included. */
function boundNames(name: ts.BindingName): string[] {
  if (ts.isIdentifier(name)) return name.text === "this" ? [] : [name.text];
  const names: string[] = [];
  for (const element of name.elements) {
    if (ts.isOmittedExpression(element)) continue;
    names.push(...boundNames(element.name));
  }
  return names;
}

function parametersOf(fn: ts.Node | undefined): readonly ts.ParameterDeclaration[] {
  return (fn as ts.FunctionLikeDeclaration | undefined)?.parameters ?? [];
}

/** A function declared or bound anywhere in this file under the given name. */
function localFunction(file: ParsedFile, name: string): ts.Node | undefined {
  for (const declaration of collect(file.source, ts.isFunctionDeclaration)) {
    if (declaration.name?.text === name && declaration.body) return declaration;
  }
  for (const declaration of collect(file.source, ts.isVariableDeclaration)) {
    if (!ts.isIdentifier(declaration.name) || declaration.name.text !== name) continue;
    const fn = functionOf(declaration.initializer);
    if (fn) return fn;
  }
  return undefined;
}

/**
 * The function a builder argument stands for.
 *
 * Three spellings reach the same body: the function written inline, a name
 * declared elsewhere in the file, and a further `.handler(fn)` call, which is how
 * a TanStack server route attaches middleware to one verb. Resolving the name is
 * what keeps a route whose handlers are defined above the registration from
 * having no body to analyse at all.
 */
function handlerFunction(file: ParsedFile, value: ts.Node | undefined, depth = 0): ts.Node | undefined {
  if (!value || depth > 4) return undefined;
  const direct = functionOf(value);
  if (direct) return direct;
  if (ts.isIdentifier(value)) return localFunction(file, value.text);
  if (ts.isCallExpression(value) && calleeTail(value) === "handler") {
    return handlerFunction(file, value.arguments[0], depth + 1);
  }
  return undefined;
}

/**
 * The name a value ends up bound to, read from the declaration around it.
 *
 * A server function's address is the identifier the client imports, and that
 * identifier sits several nodes above the handler: `export const approve =
 * createServerFn().validator(v).handler(fn)` binds the whole chain, not the
 * function. Walking out through the call and property links is what recovers it;
 * anything else — an argument position, a return statement — is not a name and
 * stops the walk rather than guessing.
 */
function boundName(node: ts.Node): string | null {
  let current: ts.Node | undefined = node.parent;
  for (let depth = 0; current && depth < 8; depth += 1) {
    if (ts.isVariableDeclaration(current)) return ts.isIdentifier(current.name) ? current.name.text : null;
    if (ts.isPropertyAssignment(current)) {
      const name = current.name;
      return ts.isIdentifier(name) || ts.isStringLiteralLike(name) ? name.text : null;
    }
    if (ts.isExportAssignment(current)) return "default";
    if (
      ts.isCallExpression(current) ||
      ts.isPropertyAccessExpression(current) ||
      ts.isParenthesizedExpression(current) ||
      ts.isAsExpression(current) ||
      ts.isSatisfiesExpression(current) ||
      ts.isNonNullExpression(current) ||
      ts.isAwaitExpression(current)
    ) {
      current = current.parent;
      continue;
    }
    return null;
  }
  return null;
}

/** The innermost call of a fluent chain, which is where the factory was invoked. */
function chainRoot(call: ts.CallExpression): ts.CallExpression {
  let current = call;
  for (let depth = 0; depth < 12; depth += 1) {
    const inner = innerCall(current.expression);
    if (!inner) return current;
    current = inner;
  }
  return current;
}

function innerCall(expression: ts.Expression): ts.CallExpression | null {
  let current: ts.Node = expression;
  for (let depth = 0; depth < 6; depth += 1) {
    if (ts.isCallExpression(current)) return current;
    if (ts.isPropertyAccessExpression(current) || ts.isParenthesizedExpression(current) || ts.isNonNullExpression(current)) {
      current = current.expression;
      continue;
    }
    return null;
  }
  return null;
}

/** An object literal, seen through the wrappers a typed declaration adds. */
function objectOf(node: ts.Node | undefined, depth = 0): ts.ObjectLiteralExpression | undefined {
  if (!node || depth > 4) return undefined;
  if (ts.isObjectLiteralExpression(node)) return node;
  if (ts.isParenthesizedExpression(node) || ts.isAsExpression(node) || ts.isSatisfiesExpression(node)) {
    return objectOf(node.expression, depth + 1);
  }
  // `.methods((api) => ({ POST: api.handler(fn) }))` is how a verb gets its own
  // middleware; the handlers live in the object that callback returns.
  if (ts.isArrowFunction(node)) {
    if (!ts.isBlock(node.body)) return objectOf(node.body, depth + 1);
    for (const statement of node.body.statements) {
      if (ts.isReturnStatement(statement) && statement.expression) return objectOf(statement.expression, depth + 1);
    }
  }
  return undefined;
}

function propertyKey(file: ParsedFile, property: ts.ObjectLiteralElementLike): string {
  if (!property.name) return "";
  if (ts.isIdentifier(property.name) || ts.isStringLiteralLike(property.name)) return property.name.text;
  return property.name.getText(file.source).replace(/["'`]/g, "");
}

function memberValue(file: ParsedFile, object: ts.ObjectLiteralExpression, key: string): ts.Expression | undefined {
  for (const property of object.properties) {
    if (propertyKey(file, property) !== key) continue;
    if (ts.isPropertyAssignment(property)) return property.initializer;
    if (ts.isShorthandPropertyAssignment(property)) return property.name;
  }
  return undefined;
}

/**
 * The local names this file imported from a matching module.
 *
 * `action` and `query` are words a project uses for its own helpers, so the
 * import gate is not "does this file mention Solid" but "is *this* identifier the
 * one Solid exported". Without that, a repository with its own `action()` builder
 * would have every call to it announced as a network endpoint.
 */
function importedNames(file: ParsedFile, pattern: RegExp): Set<string> {
  const names = new Set<string>();

  for (const statement of file.source.statements) {
    if (ts.isImportDeclaration(statement) && ts.isStringLiteralLike(statement.moduleSpecifier)) {
      if (!pattern.test(statement.moduleSpecifier.text)) continue;
      const clause = statement.importClause;
      if (!clause) continue;
      if (clause.name) names.add(clause.name.text);
      const bindings = clause.namedBindings;
      if (!bindings) continue;
      if (ts.isNamespaceImport(bindings)) names.add(bindings.name.text);
      else for (const element of bindings.elements) names.add(element.name.text);
      continue;
    }

    // `const { action } = require("@solidjs/router")` is the same dependency in a
    // plain `.js` file, and a route module written that way is still a route.
    if (!ts.isVariableStatement(statement)) continue;
    for (const declaration of statement.declarationList.declarations) {
      const initializer = declaration.initializer;
      if (!initializer || !ts.isCallExpression(initializer)) continue;
      if (initializer.expression.getText(file.source) !== "require") continue;
      const specifier = initializer.arguments[0];
      if (!specifier || !ts.isStringLiteralLike(specifier) || !pattern.test(specifier.text)) continue;
      for (const name of boundNames(declaration.name)) names.add(name);
    }
  }

  return names;
}

/** Was this call made through one of the names the framework exported? */
function callsImportedName(call: ts.CallExpression, names: Set<string>): boolean {
  const callee = call.expression;
  if (ts.isIdentifier(callee)) return names.has(callee.text);
  // A namespace import addresses the same export as `router.action(…)`.
  if (ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.expression)) return names.has(callee.expression.text);
  return false;
}

/* ------------------------------------------------------------------ *
 * Seeds
 * ------------------------------------------------------------------ */

/**
 * Every argument of a server function, seeded.
 *
 * A server function's parameters are the request: the client serialises them,
 * posts them, and the framework hands them straight to this body. React's own
 * documentation for the directive says the same thing in words — treat every
 * argument as untrusted input — and it is the only reason a mass assignment or an
 * injection inside one of these bodies is reachable at all.
 */
function argumentSeeds(fn: ts.Node | undefined): TaintSeed[] {
  const seeds: TaintSeed[] = [];
  for (const parameter of parametersOf(fn)) {
    for (const name of boundNames(parameter.name)) {
      seeds.push({ name, origin: `${name} (caller-supplied server-function argument)` });
    }
  }
  return seeds;
}

/**
 * The bindings a destructured argument bag introduces, split by who filled them.
 *
 * Only the keys named here are answered for. A key nobody listed is left alone
 * rather than guessed at: seeding one that the framework fills would put attacker
 * control on server-derived data across all thirty-six data-flow rules at once,
 * and that is a worse outcome than the coverage the guess would buy.
 */
function bagBindings(
  fn: ts.Node | undefined,
  seedOrigins: Map<string, string>,
  serverFilled: Set<string>
): { seeds: TaintSeed[]; trusted: string[] } {
  const parameter = parametersOf(fn)[0];
  if (!parameter || !ts.isObjectBindingPattern(parameter.name)) return { seeds: [], trusted: [] };

  const seeds: TaintSeed[] = [];
  const trusted: string[] = [];
  for (const element of parameter.name.elements) {
    // `...rest` holds whichever keys were not named above it, and which those are
    // cannot be known here.
    if (element.dotDotDotToken || !ts.isIdentifier(element.name)) continue;
    const key = element.propertyName ?? element.name;
    if (!ts.isIdentifier(key) && !ts.isStringLiteralLike(key)) continue;

    const origin = seedOrigins.get(key.text);
    // The bound name, not the key: `{ data: payload }` puts the caller's input in
    // `payload`, and a seed on `data` would name a binding that does not exist.
    if (origin) seeds.push({ name: element.name.text, origin });
    else if (serverFilled.has(key.text)) trusted.push(element.name.text);
  }
  return { seeds, trusted };
}

/** TanStack hands the handler one bag; only `data` inside it is the caller's. */
const SERVER_FN_SEEDS = new Map([["data", "data (caller-supplied server-function input)"]]);

/**
 * `context` is assembled by the middleware chain — a resolved session, a tenant,
 * a database handle. It reads exactly like request data to the generic parameter
 * model, which is why it has to be declared trusted here: flows derived from it
 * would be flows the caller never influenced.
 */
const SERVER_FN_TRUSTED = new Set(["context"]);

/** A route handler's bag: the request and the path parameters are the caller's. */
const ROUTE_EVENT_SEEDS = new Map([
  ["request", "request (inbound request)"],
  ["params", "params (caller-controlled route parameters)"]
]);

/** `locals` is whatever a server middleware attached, and `context` likewise. */
const ROUTE_EVENT_TRUSTED = new Set(["context", "locals"]);

function withBindings(fn: ts.Node | undefined, seeds: TaintSeed[], trusted: string[]): Partial<EntryPoint> {
  return {
    ...(fn ? { node: fn } : {}),
    ...(seeds.length > 0 ? { seeds } : {}),
    ...(trusted.length > 0 ? { trustedParameters: trusted } : {})
  };
}

/* ------------------------------------------------------------------ *
 * TanStack Start: createServerFn
 * ------------------------------------------------------------------ */

/** The verb the options object declares, defaulting to the POST the client sends. */
function serverFnMethod(file: ParsedFile, factory: ts.CallExpression): string {
  const options = objectOf(factory.arguments[0]);
  const declared = options ? memberValue(file, options, "method") : undefined;
  const literal = declared ? literalTextOf(declared) : null;
  if (!literal) return "POST";
  const method = literal.toUpperCase();
  return HTTP_VERBS.has(method) ? method : "POST";
}

function serverFunctionEntry(
  file: ParsedFile,
  site: ts.Node,
  method: string,
  name: string | null,
  fn: ts.Node | undefined,
  bindings: { seeds: TaintSeed[]; trusted: string[] }
): EntryPoint {
  return {
    framework: "tanstack-start",
    // A server function is invoked by a client component the way a form invokes
    // an action, and it answers its caller with whatever it returns.
    kind: "action",
    method,
    path: name ?? UNNAMED,
    line: lineOf(file, site),
    ...withBindings(fn, bindings.seeds, bindings.trusted)
  };
}

function tanstackServerFunctions(file: ParsedFile, claimed: Set<ts.Node>): EntryPoint[] {
  if (!importsFrom(file, TANSTACK_MODULES)) return [];
  const found: EntryPoint[] = [];

  for (const call of allCalls(file)) {
    // The builder form: createServerFn(options).middleware(…).validator(…).handler(fn).
    if (calleeTail(call) === "handler") {
      const factory = chainRoot(call);
      if (factory === call || calleeTail(factory) !== "createServerFn") continue;
      const fn = handlerFunction(file, call.arguments[0]);
      if (fn) {
        if (claimed.has(fn)) continue;
        claimed.add(fn);
      }
      found.push(
        serverFunctionEntry(
          file,
          factory,
          serverFnMethod(file, factory),
          boundName(factory),
          fn,
          // An identifier parameter holds the whole bag, `context` included, and
          // there is no way to seed one key of it. Left unseeded on purpose: the
          // generic model already reads a parameter called `ctx` as request data,
          // and seeding the bag outright would mark the middleware's own output
          // as something the caller chose.
          bagBindings(fn, SERVER_FN_SEEDS, SERVER_FN_TRUSTED)
        )
      );
      continue;
    }

    // The original two-argument form, `createServerFn("POST", async (payload, ctx) => …)`,
    // which is still what an application written against the early releases uses.
    if (calleeTail(call) !== "createServerFn") continue;
    const fn = handlerFunction(file, call.arguments[1]);
    if (!fn || claimed.has(fn)) continue;
    claimed.add(fn);

    const declared = call.arguments[0] ? literalTextOf(call.arguments[0]!) : null;
    const method = declared && HTTP_VERBS.has(declared.toUpperCase()) ? declared.toUpperCase() : "POST";
    const payload = parametersOf(fn)[0];
    // Here the payload *is* the first parameter rather than a key of a bag, so an
    // identifier can be seeded outright. The second parameter is the framework's
    // own context and is named as trusted for the same reason as above.
    const seeds: TaintSeed[] =
      payload && ts.isIdentifier(payload.name)
        ? [{ name: payload.name.text, origin: "data (caller-supplied server-function input)" }]
        : [];
    const second = parametersOf(fn)[1];
    const trusted = second && ts.isIdentifier(second.name) ? [second.name.text] : [];
    found.push(serverFunctionEntry(file, call, method, boundName(call), fn, { seeds, trusted }));
  }

  return found;
}

/* ------------------------------------------------------------------ *
 * TanStack Start: server routes
 * ------------------------------------------------------------------ */

interface RouteHandlers {
  factory: ts.CallExpression;
  handlers: ts.ObjectLiteralExpression;
}

/**
 * The verb map of a server route, in both spellings the framework has shipped.
 *
 * `createServerFileRoute("/api/x").methods({ GET })` is the current form and
 * `createAPIFileRoute("/api/x")({ GET })` the earlier curried one. They declare
 * the same thing, and a project part-way through an upgrade contains both.
 */
function routeHandlers(file: ParsedFile, call: ts.CallExpression): RouteHandlers | null {
  if (calleeTail(call) === "methods") {
    const factory = chainRoot(call);
    if (factory === call || !TANSTACK_ROUTE_FACTORIES.has(calleeTail(factory))) return null;
    const handlers = objectOf(call.arguments[0]);
    return handlers ? { factory, handlers } : null;
  }
  if (!ts.isCallExpression(call.expression)) return null;
  if (!TANSTACK_ROUTE_FACTORIES.has(calleeTail(call.expression))) return null;
  const handlers = objectOf(call.arguments[0]);
  return handlers ? { factory: call.expression, handlers } : null;
}

/**
 * The route a server-route file declares from its own location.
 *
 * Only used when the factory was called without its path, which is what the
 * generated form looks like. Anything the file name cannot settle — an escaped
 * segment, a name with brackets in it — returns null so the caller reports `/`
 * instead: a wrong address sends the reader to an endpoint that does not exist,
 * which is worse than admitting the path is unknown.
 */
function tanstackRoutePath(relativePath: string): string | null {
  const parts = relativePath.split("/").filter((part) => part.length > 0);
  const fileName = parts.pop();
  if (!fileName || !SOURCE_EXTENSION.test(fileName)) return null;

  const root = parts.lastIndexOf("routes");
  if (root === -1) return null;
  const directories = parts.slice(root + 1).filter((part) => !(part.startsWith("(") && part.endsWith(")")));

  const base = fileName.replace(SOURCE_EXTENSION, "");
  // Flat routes spell a separator with a dot, so `api.orders.$id.ts` is three
  // segments. An escaped `[.]` means the dot is part of the name instead.
  if (base.includes("[") || base.includes("]")) return null;
  const leaf = base
    .split(".")
    .filter((segment) => segment.length > 0 && segment !== "index" && segment !== "route")
    .filter((segment) => !(segment.startsWith("(") && segment.endsWith(")")));

  return joinRoute(...directories, ...leaf);
}

function tanstackServerRoutes(file: ParsedFile, claimed: Set<ts.Node>): EntryPoint[] {
  if (!importsFrom(file, TANSTACK_MODULES)) return [];
  const found: EntryPoint[] = [];

  for (const call of allCalls(file)) {
    const route = routeHandlers(file, call);
    if (!route) continue;

    const declared = route.factory.arguments[0] ? literalTextOf(route.factory.arguments[0]!) : null;
    const path = declared ?? tanstackRoutePath(file.relativePath) ?? "/";

    for (const property of route.handlers.properties) {
      const method = propertyKey(file, property).toUpperCase();
      if (!HTTP_VERBS.has(method)) continue;

      const fn = ts.isMethodDeclaration(property)
        ? property
        : ts.isPropertyAssignment(property)
          ? handlerFunction(file, property.initializer)
          : ts.isShorthandPropertyAssignment(property)
            ? localFunction(file, property.name.text)
            : undefined;
      if (fn) {
        if (claimed.has(fn)) continue;
        claimed.add(fn);
      }

      const bindings = bagBindings(fn, ROUTE_EVENT_SEEDS, ROUTE_EVENT_TRUSTED);
      found.push({
        framework: "tanstack-start",
        kind: "http",
        method,
        path,
        line: lineOf(file, property),
        ...withBindings(fn, bindings.seeds, bindings.trusted)
      });
    }
  }

  return found;
}

/* ------------------------------------------------------------------ *
 * SolidStart: action(), query() and the "use server" directive
 * ------------------------------------------------------------------ */

function solidEntry(
  file: ParsedFile,
  site: ts.Node,
  name: string | null,
  fn: ts.Node | undefined,
  framework: string
): EntryPoint {
  // Seeds only when the function really crosses the network. A SolidStart
  // `action` without the directive is compiled for the browser and runs there, so
  // announcing its arguments as caller-controlled server input would put taint on
  // client code that never sees a request.
  const seeds = hasServerDirective(fn) || isServerModule(file) ? argumentSeeds(fn) : [];
  return {
    framework,
    kind: "action",
    method: "POST",
    path: name ?? UNNAMED,
    line: lineOf(file, site),
    ...withBindings(fn, seeds, [])
  };
}

/**
 * `action(fn, "name")` and `query(fn, "key")`, the two ways SolidStart publishes
 * a function the client calls by name.
 *
 * The second argument is the name the framework registers, which is a better
 * address than the variable when the two differ, and the only address at all when
 * the call is passed straight to a component. `cache` is the name `query` had
 * before Solid Router 0.15 and behaves identically.
 */
function solidRpcFactories(file: ParsedFile, claimed: Set<ts.Node>): EntryPoint[] {
  const names = importedNames(file, SOLID_MODULES);
  if (names.size === 0) return [];

  const found: EntryPoint[] = [];
  for (const call of allCalls(file)) {
    if (!SOLID_RPC_FACTORIES.has(calleeTail(call))) continue;
    if (!callsImportedName(call, names)) continue;

    const fn = handlerFunction(file, call.arguments[0]);
    if (!fn || claimed.has(fn)) continue;
    claimed.add(fn);

    const declared = call.arguments[1] ? literalTextOf(call.arguments[1]!) : null;
    found.push(solidEntry(file, call, declared ?? boundName(call), fn, "solid-start"));
  }
  return found;
}

/**
 * A function whose own body opens with the directive.
 *
 * This is the shape that hides best: the module is ordinary, the export is
 * ordinary, and one line inside the body turns that function alone into an
 * endpoint. It is also how SolidStart's own documentation writes a server
 * function, so missing it would leave the framework's primary form unrecognised.
 */
function directiveFunctions(file: ParsedFile, claimed: Set<ts.Node>, framework: string): EntryPoint[] {
  const found: EntryPoint[] = [];
  for (const fn of collect(file.source, isFunctionLike)) {
    if (claimed.has(fn) || !hasServerDirective(fn)) continue;
    claimed.add(fn);
    found.push({
      framework,
      kind: "action",
      method: "POST",
      path: declaredName(fn) ?? boundName(fn) ?? UNNAMED,
      line: lineOf(file, fn),
      ...withBindings(fn, argumentSeeds(fn), [])
    });
  }
  return found;
}

function isFunctionLike(node: ts.Node): node is ts.FunctionLikeDeclaration {
  return ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node) || ts.isArrowFunction(node) || ts.isMethodDeclaration(node);
}

/** The name a function declaration or a named function expression carries. */
function declaredName(fn: ts.Node): string | null {
  if ((ts.isFunctionDeclaration(fn) || ts.isFunctionExpression(fn)) && fn.name) return fn.name.text;
  if (ts.isMethodDeclaration(fn) && ts.isIdentifier(fn.name)) return fn.name.text;
  return null;
}

/* ------------------------------------------------------------------ *
 * A "use server" module
 * ------------------------------------------------------------------ */

interface ExportedFunction {
  name: string;
  fn: ts.Node;
  /** The node a reader would point at, which is the export, not the body. */
  declaration: ts.Node;
}

function hasModifier(node: ts.Node, kind: ts.SyntaxKind): boolean {
  return ts.canHaveModifiers(node) && (ts.getModifiers(node)?.some((modifier) => modifier.kind === kind) ?? false);
}

/**
 * Every function this module exports, under the name the client will import.
 *
 * In a `"use server"` module that name is the address: the bundler turns each
 * export into its own callable endpoint, so an unexported helper in the same file
 * is not reachable and must not be announced as though it were.
 */
function exportedFunctions(file: ParsedFile): ExportedFunction[] {
  const found: ExportedFunction[] = [];
  const add = (name: string, fn: ts.Node | undefined, declaration: ts.Node): void => {
    if (fn) found.push({ name, fn, declaration });
  };

  for (const statement of file.source.statements) {
    if (ts.isFunctionDeclaration(statement) && hasModifier(statement, ts.SyntaxKind.ExportKeyword)) {
      if (statement.body) add(statement.name?.text ?? "default", statement, statement);
      continue;
    }

    if (ts.isVariableStatement(statement) && hasModifier(statement, ts.SyntaxKind.ExportKeyword)) {
      for (const declaration of statement.declarationList.declarations) {
        if (!ts.isIdentifier(declaration.name)) continue;
        add(declaration.name.text, functionOf(declaration.initializer), declaration);
      }
      continue;
    }

    if (ts.isExportAssignment(statement)) {
      const value = functionOf(statement.expression);
      const name = ts.isIdentifier(statement.expression) ? statement.expression.text : "default";
      add(name, value ?? (ts.isIdentifier(statement.expression) ? localFunction(file, statement.expression.text) : undefined), statement);
      continue;
    }

    // `const save = async () => {}; export { save };` is the same export written
    // apart from the definition.
    if (ts.isExportDeclaration(statement) && statement.exportClause && !statement.moduleSpecifier) {
      if (!ts.isNamedExports(statement.exportClause)) continue;
      for (const element of statement.exportClause.elements) {
        add(element.name.text, localFunction(file, (element.propertyName ?? element.name).text), element);
      }
      continue;
    }

    // `exports.save = async () => {}` and `module.exports = { save }`, which is
    // what a plain `.js` server module still looks like.
    if (!ts.isExpressionStatement(statement)) continue;
    const assignment = statement.expression;
    if (!ts.isBinaryExpression(assignment) || assignment.operatorToken.kind !== ts.SyntaxKind.EqualsToken) continue;
    const target = assignment.left.getText(file.source).replace(/\s+/g, "");
    const named = /^(?:module\.)?exports\.(.+)$/.exec(target);
    if (named) {
      const value = functionOf(assignment.right) ?? (ts.isIdentifier(assignment.right) ? localFunction(file, assignment.right.text) : undefined);
      add(named[1]!, value, statement);
      continue;
    }
    if (target !== "module.exports" && target !== "exports") continue;
    const whole = functionOf(assignment.right);
    if (whole) {
      add("default", whole, statement);
      continue;
    }
    const object = objectOf(assignment.right);
    if (!object) continue;
    for (const property of object.properties) {
      const key = propertyKey(file, property);
      if (!key) continue;
      if (ts.isMethodDeclaration(property)) add(key, property, property);
      else if (ts.isPropertyAssignment(property)) add(key, functionOf(property.initializer), property);
      else if (ts.isShorthandPropertyAssignment(property)) add(key, localFunction(file, property.name.text), property);
    }
  }

  return found;
}

function serverModuleEntries(file: ParsedFile, claimed: Set<ts.Node>, framework: string): EntryPoint[] {
  const found: EntryPoint[] = [];
  for (const exported of exportedFunctions(file)) {
    if (claimed.has(exported.fn)) continue;
    claimed.add(exported.fn);
    found.push({
      framework,
      kind: "action",
      method: "POST",
      path: exported.name,
      line: lineOf(file, exported.declaration),
      ...withBindings(exported.fn, argumentSeeds(exported.fn), [])
    });
  }
  return found;
}

/* ------------------------------------------------------------------ *
 * SolidStart API routes
 * ------------------------------------------------------------------ */

/**
 * The URL a SolidStart route file answers on.
 *
 * The bracket segments are kept exactly as the directory spells them — `[id]`,
 * `[...rest]` — because that is what the developer wrote, what the SolidStart
 * documentation calls it, and what they will search the report for. A group
 * directory exists to share a layout rather than to add a segment, so `(app)`
 * contributes nothing to the path.
 */
function solidRoutePath(relativePath: string): string | null {
  const parts = relativePath.split("/").filter((part) => part.length > 0);
  const fileName = parts.pop();
  if (!fileName || !SOURCE_EXTENSION.test(fileName)) return null;

  const root = parts.lastIndexOf("routes");
  if (root === -1) return null;
  const directories = parts.slice(root + 1).filter((part) => !(part.startsWith("(") && part.endsWith(")")));

  const base = fileName.replace(SOURCE_EXTENSION, "");
  // `index.ts` answers the directory it sits in rather than a segment of its own.
  const leaf = base === "index" ? [] : [base];
  return joinRoute(...directories, ...leaf);
}

/**
 * A SolidStart API route: an HTTP verb exported from a file under `routes/`.
 *
 * The verb name is the whole registration — there is no call anywhere to find —
 * and the handler is given one `APIEvent`, which is a bag exactly like the one
 * SvelteKit passes: `request` and `params` are the caller's, `locals` is whatever
 * a middleware attached.
 */
function solidApiRoutes(file: ParsedFile, claimed: Set<ts.Node>): EntryPoint[] {
  const path = solidRoutePath(file.relativePath);
  if (path === null || !importsFrom(file, SOLID_MODULES)) return [];

  const found: EntryPoint[] = [];
  for (const exported of exportedFunctions(file)) {
    const method = exported.name.toUpperCase();
    if (!HTTP_VERBS.has(method) || claimed.has(exported.fn)) continue;
    claimed.add(exported.fn);

    const parameter = parametersOf(exported.fn)[0];
    const whole =
      parameter && ts.isIdentifier(parameter.name)
        ? [{ name: parameter.name.text, origin: "event (inbound request)" }]
        : [];
    const bindings = bagBindings(exported.fn, ROUTE_EVENT_SEEDS, ROUTE_EVENT_TRUSTED);

    found.push({
      framework: "solid-start",
      kind: "http",
      method,
      path,
      line: lineOf(file, exported.declaration),
      ...withBindings(exported.fn, whole.length > 0 ? whole : bindings.seeds, bindings.trusted)
    });
  }
  return found;
}

/* ------------------------------------------------------------------ *
 * The adapter
 * ------------------------------------------------------------------ */

/**
 * The text pre-check.
 *
 * It runs for every adapter over every file, so each clause names a token that
 * belongs to nothing else: the quoted directive, a TanStack factory beside a
 * TanStack import, or a Solid import beside something Solid publishes. `detect`
 * re-checks every one of them against the AST, which is what keeps the phrase
 * `"use server"` inside a comment or a documentation string from claiming a file.
 */
function applies(file: ParsedFile): boolean {
  const text = file.text;
  if (/["']use server["']/.test(text)) return true;

  if (/@tanstack\//.test(text) && /\bcreate(?:ServerFn|ServerFileRoute|ServerRoute|APIFileRoute)\b/.test(text)) return true;

  if (!/["']@solidjs\/(?:router|start)|["']solid-js/.test(text)) return false;
  if (/\b(?:action|query|cache)\s*\(/.test(text)) return true;
  return solidRoutePath(file.relativePath) !== null && /\b(?:GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\b/.test(text);
}

function detect(file: ParsedFile): EntryPoint[] {
  // One function is one entry point. A `"use server"` module whose exports are
  // also wrapped in `action()` matches two shapes, and announcing both would put
  // the same body in the report twice under two addresses. The order runs the
  // shapes that know their own address before the ones that fall back to a name.
  const claimed = new Set<ts.Node>();

  // The framework label is only claimed when an import proves it. A module that
  // carries nothing but the directive is a server function under React's own
  // convention — Next.js, Waku and Redwood compile it identically — and naming a
  // framework it does not import would be a guess in the coverage report.
  const framework = importsFrom(file, SOLID_MODULES)
    ? "solid-start"
    : importsFrom(file, TANSTACK_MODULES)
      ? "tanstack-start"
      : "server-function";

  const found: EntryPoint[] = [
    ...tanstackServerRoutes(file, claimed),
    ...tanstackServerFunctions(file, claimed),
    ...solidApiRoutes(file, claimed),
    ...solidRpcFactories(file, claimed),
    ...directiveFunctions(file, claimed, framework)
  ];

  if (isServerModule(file)) found.push(...serverModuleEntries(file, claimed, framework));
  return found;
}

export const tanstackSolidAdapter: FrameworkAdapter = { id: "tanstack-solid", applies, detect };

/**
 * TanStack Start and SolidStart are one adapter on purpose.
 *
 * The two frameworks share the shape that matters — a function the compiler turns
 * into an endpoint — and they overlap inside single files: TanStack Start ships a
 * Solid binding, and a `"use server"` module gives no import at all to tell them
 * apart. Run as separate adapters they would each claim the same function, and
 * the report would carry one body twice under two addresses. One pass with one
 * claimed set is what prevents that; `registerAdapter` deduplicates by id, so
 * registering either of these names registers the pass once.
 */
export const tanstackStartAdapter = tanstackSolidAdapter;
export const solidStartAdapter = tanstackSolidAdapter;
