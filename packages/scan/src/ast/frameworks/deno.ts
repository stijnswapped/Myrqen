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
import { collect, enclosingFunction, expressionName, literalTextOf } from "../helpers.js";
import { lineOf, type ParsedFile } from "../parse.js";

/* ------------------------------------------------------------------------- *
 * Deno: Deno.serve, Deno.serveHttp, std/http's serve, and Fresh
 *
 * A Deno service registers nothing that route discovery can read. There is no
 * `app.get("/orders/:id", handler)` and no exported name a convention looks for:
 * the whole server is one call to a global — `Deno.serve(handler)` — and the
 * handler is an anonymous function whose only parameter is a `Request`. Nothing
 * in that shape resembles an entry point to a model built around registration
 * calls, so the file is invisible, and invisibility is total: with no entry point
 * no binding is caller-controlled, and every data-flow rule stays silent over a
 * handler that reads `url.searchParams.get("q")` straight into a query.
 *
 * The address is the honest half of the problem. A `Deno.serve` handler answers
 * every path the process is reachable at; the routing, when there is any, is a
 * chain of comparisons inside the body. So the address is `ANY /` unless the body
 * settles it — one pathname compared against one literal — and a Fresh route,
 * which really does declare its path in its file name, takes it from there.
 * Inventing a path for a server that serves everything would send the reader
 * looking for an endpoint that does not exist.
 *
 * Two Deno shapes are deliberately left to `serverless.ts`, which already claims
 * them for every runtime that accepts them: `export default { fetch(request) {} }`
 * and `addEventListener("fetch", …)`. Both are recognised there with the same
 * seeds and the same address this file would give them, and a second claim would
 * put one handler in the report twice under two framework names.
 * ------------------------------------------------------------------------- */

/** Origins are quoted verbatim in evidence, so they read as what a reader would look for. */
const REQUEST_ORIGIN = "request (inbound request)";
/** A Fresh handler's second parameter is the context, and its route parameters are the caller's. */
const ROUTE_PARAMS_ORIGIN = "ctx.params (route parameters)";
/** Fresh 2 collapses the pair into one context that carries the request as well. */
const FRESH_CONTEXT_ORIGIN = "ctx (inbound request and route parameters)";
/**
 * `Deno.serveHttp` yields request events rather than requests, so the origin is
 * built from the loop variable's own name: the reader is looking for a binding
 * that only exists in that loop, and a fixed wording would name one that is not
 * in the file.
 */
const requestEventOrigin = (name: string): string => `${name}.request (inbound request)`;

const HTTP_METHOD = /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$/;

/** The keys Fresh reads off a handler object. Anything else in it is not a route. */
const FRESH_VERBS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]);

const SOURCE_EXTENSION = /\.[cm]?[jt]sx?$/;

/** `Deno.serve` and `Deno.serveHttp`, including the spelled-out global. */
const DENO_SERVE = /^(?:globalThis\.|self\.)?Deno\.serve$/;
const DENO_SERVE_HTTP = /^(?:globalThis\.|self\.)?Deno\.serveHttp$/;

/**
 * The standard library's own HTTP server, which predates `Deno.serve` and is
 * still what a great deal of published Deno code calls.
 *
 * `serve` is far too common a name to recognise on its own — half the Node
 * ecosystem exports one — so the import is what settles that this particular call
 * is Deno's. Its handler comes first and its options second, the opposite way
 * round from `Deno.serve`, which is the detail that makes it worth handling
 * separately rather than folding into the same argument scan.
 */
const STD_HTTP = /(^|\/)deno\.land\/std[^/]*\/http\/|^jsr:@std\/http|^@std\/http/;
const STD_SERVE = /^(?:serve|serveTls)$/;

/**
 * Fresh's own modules, under every specifier the framework has shipped.
 *
 * The import matters because `routes/` is an ordinary directory name: an Express
 * project keeps its route modules there too, and one of those can export a
 * function called `handler` with a signature that has nothing to do with Fresh.
 * Seeding its second parameter as route parameters would put attacker control on
 * whatever that project's second parameter really is.
 */
const FRESH_MODULES = /^\$fresh\/|^jsr:@fresh\/|^@fresh\/|(^|\/)deno\.land\/x\/fresh|^fresh\/(server|runtime)/;

/**
 * Fresh types that no other framework exports under the same name.
 *
 * `Handler` in the singular is missing on purpose: Express, Hono and Koa all
 * export one, and an Express `Handler` is `(req, res, next)` — treating its
 * second parameter as route parameters would make the response object look like
 * caller data in every rule at once.
 */
const FRESH_TYPE = /\b(?:Handlers|FreshContext|HandlerContext|RouteContext)\b/;

interface Address {
  method: string;
  path: string;
}

/** A handler that has not been placed: the seeds still matter, the label does not. */
const UNPLACED: Address = { method: "ANY", path: "/" };

/* ------------------------------- plumbing ------------------------------- */

function hasModifier(node: ts.Node, kind: ts.SyntaxKind): boolean {
  return ts.canHaveModifiers(node) && (ts.getModifiers(node)?.some((modifier) => modifier.kind === kind) ?? false);
}

/** An object literal seen through the `as const` and `satisfies Config` wrappers. */
function unwrapObject(node: ts.Expression | undefined): ts.ObjectLiteralExpression | undefined {
  let current = node;
  for (let depth = 0; current && depth < 4; depth += 1) {
    if (ts.isObjectLiteralExpression(current)) return current;
    if (ts.isAsExpression(current) || ts.isSatisfiesExpression(current) || ts.isParenthesizedExpression(current)) {
      current = current.expression;
      continue;
    }
    return undefined;
  }
  return undefined;
}

/** An expression with the wrappers that do not change what it denotes removed. */
function unwrapExpression(node: ts.Expression): ts.Expression {
  let current = node;
  for (let depth = 0; depth < 4; depth += 1) {
    if (ts.isParenthesizedExpression(current) || ts.isAwaitExpression(current) || ts.isNonNullExpression(current)) {
      current = current.expression;
      continue;
    }
    if (ts.isAsExpression(current) || ts.isSatisfiesExpression(current)) {
      current = current.expression;
      continue;
    }
    return current;
  }
  return current;
}

function propertyKey(file: ParsedFile, property: ts.ObjectLiteralElementLike): string {
  if (!property.name) return "";
  if (ts.isIdentifier(property.name) || ts.isStringLiteralLike(property.name)) return property.name.text;
  return property.name.getText(file.source).replace(/["'`]/g, "");
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

/** The function a value stands for, following a name declared in the same file. */
function functionValue(file: ParsedFile, value: ts.Expression | undefined): ts.Node | undefined {
  if (!value) return undefined;
  const direct = functionOf(value);
  if (direct) return direct;
  return ts.isIdentifier(value) ? localFunction(file, value.text) : undefined;
}

/** The function held by one member, including the `async fetch() {}` method form. */
function memberFunction(file: ParsedFile, object: ts.ObjectLiteralExpression, key: string): ts.Node | undefined {
  for (const property of object.properties) {
    if (propertyKey(file, property) !== key) continue;
    if (ts.isMethodDeclaration(property) && property.body) return property;
    if (ts.isPropertyAssignment(property)) return functionValue(file, property.initializer);
    if (ts.isShorthandPropertyAssignment(property)) return localFunction(file, property.name.text);
  }
  return undefined;
}

function isEquality(kind: ts.SyntaxKind): boolean {
  return (
    kind === ts.SyntaxKind.EqualsEqualsEqualsToken ||
    kind === ts.SyntaxKind.EqualsEqualsToken ||
    kind === ts.SyntaxKind.ExclamationEqualsEqualsToken ||
    kind === ts.SyntaxKind.ExclamationEqualsToken
  );
}

/**
 * The verb and path a handler settles on by comparing against literals.
 *
 * Only an unambiguous answer counts. A handler that compares its pathname
 * against three different literals is a dispatcher with three addresses, and
 * labelling the whole body with whichever branch happens to come first would
 * attribute findings in the other two to an endpoint they are not on. Route
 * discovery already recovers those branches individually, so this stays quiet
 * and leaves the handler at `ANY /`.
 */
function addressFromBody(fn: ts.Node | undefined, methodAccessors: readonly string[]): Address {
  if (!fn) return { ...UNPLACED };

  const methods = new Set<string>();
  const paths = new Set<string>();

  for (const comparison of collect(fn, ts.isBinaryExpression)) {
    if (!isEquality(comparison.operatorToken.kind)) continue;
    for (const [accessed, other] of [
      [comparison.left, comparison.right],
      [comparison.right, comparison.left]
    ] as const) {
      const literal = literalTextOf(other);
      if (literal === null) continue;
      const name = expressionName(accessed as ts.Expression);
      // The pathname is nearly always read off a `new URL(request.url)` local, so
      // it is recognised by its own tail rather than through the parameter.
      if (name === "pathname" || name.endsWith(".pathname")) {
        if (literal.startsWith("/")) paths.add(literal);
        continue;
      }
      if (methodAccessors.includes(name) && HTTP_METHOD.test(literal.toUpperCase())) methods.add(literal.toUpperCase());
    }
  }

  return {
    method: methods.size === 1 ? [...methods][0]! : UNPLACED.method,
    path: paths.size === 1 ? [...paths][0]! : UNPLACED.path
  };
}

/**
 * The seeds a request-shaped first parameter introduces, and the runtime's own
 * second parameter named as trusted.
 *
 * Only a plain identifier is seeded. A `Request` is useless once destructured —
 * its body and headers are methods — so a destructured parameter here is
 * something other than the request, and guessing which of its bindings hold
 * caller data is the guess that manufactures a false positive in every rule at
 * once.
 */
interface Handled {
  seeds: TaintSeed[];
  trusted: string[];
}

function requestHandler(fn: ts.Node | undefined): Handled {
  const parameters = (fn as ts.FunctionLikeDeclaration | undefined)?.parameters;
  if (!parameters || parameters.length === 0) return { seeds: [], trusted: [] };

  const first = parameters[0];
  const seeds: TaintSeed[] =
    first && ts.isIdentifier(first.name) ? [{ name: first.name.text, origin: REQUEST_ORIGIN }] : [];

  // The second argument carries the remote address and the connection's
  // lifetime, which the server learns from the socket rather than from anything
  // the caller wrote. The generic model reads a parameter called `info` or
  // `context` as attacker data, and every flow it derives from one is a lie.
  const second = parameters[1];
  const trusted = second && ts.isIdentifier(second.name) ? [second.name.text] : [];

  return { seeds, trusted };
}

function entryPoint(
  file: ParsedFile,
  address: Address,
  at: ts.Node,
  fn: ts.Node | undefined,
  handled: Handled
): EntryPoint {
  return {
    framework: "deno",
    kind: "http",
    method: address.method,
    path: address.path,
    line: lineOf(file, at),
    ...(fn ? { node: fn } : {}),
    ...(handled.seeds.length > 0 ? { seeds: handled.seeds } : {}),
    ...(handled.trusted.length > 0 ? { trustedParameters: handled.trusted } : {})
  };
}

/* --------------------------- Deno.serve and std ---------------------------- */

/**
 * The function a `Deno.serve` call will run.
 *
 * All four documented forms have to be read, because they are not stylistic
 * variants of one another: an options object is how a service sets its port, and
 * the handler moves between the first argument, the second argument, and a
 * `fetch` or `handler` member depending on which form the author picked. Missing
 * any of them loses the entry point, and losing the entry point loses the file.
 */
function serveHandler(file: ParsedFile, call: ts.CallExpression, handlerFirst: boolean): ts.Node | undefined {
  const [first, second] = [call.arguments[0], call.arguments[1]];
  if (handlerFirst) return functionValue(file, first);

  const positional = functionValue(file, second) ?? functionValue(file, first);
  if (positional) return positional;

  const options = unwrapObject(first);
  if (!options) return undefined;
  return memberFunction(file, options, "fetch") ?? memberFunction(file, options, "handler");
}

function serveEntryPoints(file: ParsedFile, claimed: Set<ts.Node>): EntryPoint[] {
  const usesStd = importsFrom(file, STD_HTTP);
  const found: EntryPoint[] = [];

  for (const call of allCalls(file)) {
    const callee = expressionName(call.expression);
    const isDeno = DENO_SERVE.test(callee);
    // `serve(handler)` is only claimed when the standard library's HTTP server is
    // the thing that was imported, because the bare name belongs to too many
    // other packages to be evidence of anything on its own.
    const isStd = usesStd && STD_SERVE.test(callee);
    if (!isDeno && !isStd) continue;
    if (call.arguments.length === 0) continue;

    const fn = serveHandler(file, call, isStd);
    if (fn && claimed.has(fn)) continue;
    if (fn) claimed.add(fn);

    const root = fn ? firstParameterName(fn) : null;
    const address = addressFromBody(fn, root ? [`${root}.method`] : []);
    found.push(entryPoint(file, address, call, fn, requestHandler(fn)));
  }

  return found;
}

function firstParameterName(fn: ts.Node): string | null {
  const parameter = (fn as ts.FunctionLikeDeclaration).parameters?.[0];
  if (!parameter || !ts.isIdentifier(parameter.name)) return null;
  return parameter.name.text;
}

/* ------------------------------ Deno.serveHttp ----------------------------- */

/**
 * The name a call's result is bound to, so the loop that consumes it can be found.
 *
 * `Deno.serveHttp` hands back an async iterable rather than taking a callback, so
 * there is no handler function to point at. The request arrives as the loop
 * variable of a `for await`, which is the only place in this whole file where the
 * caller's data enters through a binding that is not a parameter.
 */
function boundName(call: ts.CallExpression): string | null {
  let current: ts.Node | undefined = call.parent;
  for (let depth = 0; current && depth < 4; depth += 1) {
    if (ts.isVariableDeclaration(current)) {
      return ts.isIdentifier(current.name) ? current.name.text : null;
    }
    if (
      ts.isParenthesizedExpression(current) ||
      ts.isAwaitExpression(current) ||
      ts.isAsExpression(current) ||
      ts.isNonNullExpression(current)
    ) {
      current = current.parent;
      continue;
    }
    return null;
  }
  return null;
}

function requestEventLoop(file: ParsedFile, call: ts.CallExpression): ts.ForOfStatement | undefined {
  const holder = boundName(call);
  for (const loop of collect(file.source, ts.isForOfStatement)) {
    if (!loop.awaitModifier) continue;
    const iterated = unwrapExpression(loop.expression);
    if (iterated === call) return loop;
    if (holder && ts.isIdentifier(iterated) && iterated.text === holder) return loop;
  }
  return undefined;
}

/**
 * The binding each iteration puts the request event in.
 *
 * A destructured loop variable is read for its `request` element only. That one
 * binding is the caller's request with the same certainty the whole event is;
 * `respondWith` beside it is a function the server calls, and seeding it would
 * describe the response as attacker data.
 */
function loopSeeds(loop: ts.ForOfStatement): TaintSeed[] {
  const initializer = loop.initializer;
  if (!ts.isVariableDeclarationList(initializer)) return [];
  const declaration = initializer.declarations[0];
  if (!declaration) return [];

  if (ts.isIdentifier(declaration.name)) {
    return [{ name: declaration.name.text, origin: requestEventOrigin(declaration.name.text) }];
  }
  if (!ts.isObjectBindingPattern(declaration.name)) return [];

  const seeds: TaintSeed[] = [];
  for (const element of declaration.name.elements) {
    if (!ts.isIdentifier(element.name)) continue;
    const property =
      element.propertyName && ts.isIdentifier(element.propertyName) ? element.propertyName.text : element.name.text;
    if (property !== "request") continue;
    seeds.push({ name: element.name.text, origin: REQUEST_ORIGIN });
  }
  return seeds;
}

function serveHttpEntryPoints(file: ParsedFile, claimed: Set<ts.Node>): EntryPoint[] {
  const found: EntryPoint[] = [];

  for (const call of allCalls(file)) {
    if (!DENO_SERVE_HTTP.test(expressionName(call.expression))) continue;

    const loop = requestEventLoop(file, call);
    // The loop body is not a function of its own, so the entry point's handler is
    // whichever function encloses it — that is the scope the taint model will
    // analyse. A `for await` written at the top level of a module has no such
    // scope, so it gets the address and no seeds rather than a seed nothing can
    // use.
    const holder = loop ? enclosingFunction(loop) : undefined;
    if (holder && claimed.has(holder)) continue;

    const seeds = loop && holder ? loopSeeds(loop) : [];
    if (holder) claimed.add(holder);

    const root = seeds[0]?.name ?? null;
    const address = addressFromBody(holder, root ? [`${root}.request.method`, `${root}.method`] : []);
    found.push(entryPoint(file, address, call, holder, { seeds, trusted: [] }));
  }

  return found;
}

/* ---------------------------------- Fresh ---------------------------------- */

/**
 * The route a Fresh file name declares, or null when the path is not a route tree.
 *
 * Everything under `routes/` is addressable and nothing outside it is, so the
 * file name is the only statement of the path that exists anywhere in the
 * project. Bracket segments are kept exactly as written: `[id]` and `[...slug]`
 * are what the developer typed, what the Fresh documentation calls them, and what
 * they will search the report for. Parenthesised directories are route groups
 * that organise the tree without appearing in the URL.
 */
function freshRoutePath(relativePath: string): string | null {
  const parts = relativePath.split("/").filter((part) => part.length > 0);
  const fileName = parts.pop();
  if (!fileName || !SOURCE_EXTENSION.test(fileName)) return null;

  const root = parts.lastIndexOf("routes");
  if (root === -1) return null;
  const inside = parts.slice(root + 1).filter((part) => !(part.startsWith("(") && part.endsWith(")")));

  const base = fileName.replace(SOURCE_EXTENSION, "");
  if (base.startsWith("_")) {
    // `_middleware` runs for every request below its directory, which is why it is
    // reported at `/`: it has no address of its own but it does see all of them.
    // The other underscore files are the app shell, the layouts and the error
    // pages, and none of those is an endpoint a caller can reach by name.
    return base === "_middleware" ? "/" : null;
  }

  // `index` addresses the directory it sits in rather than a segment of its own.
  const leaf = base === "index" ? [] : [base];
  return joinRoute(...inside, ...leaf);
}

interface ExportedHandler {
  /** The node a reader would point at, which is the export rather than the body. */
  declaration: ts.Node;
  value?: ts.Expression;
  fn?: ts.Node;
  typeText: string;
}

/** The `handler` a Fresh route module exports, in either of the two forms Fresh reads. */
function exportedHandler(file: ParsedFile): ExportedHandler | undefined {
  for (const statement of file.source.statements) {
    if (ts.isFunctionDeclaration(statement) && statement.name?.text === "handler" && statement.body) {
      if (!hasModifier(statement, ts.SyntaxKind.ExportKeyword)) continue;
      return { declaration: statement, fn: statement, typeText: "" };
    }
    if (!ts.isVariableStatement(statement) || !hasModifier(statement, ts.SyntaxKind.ExportKeyword)) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (!ts.isIdentifier(declaration.name) || declaration.name.text !== "handler") continue;
      return {
        declaration,
        ...(declaration.initializer ? { value: declaration.initializer } : {}),
        typeText: declaration.type ? declaration.type.getText(file.source) : ""
      };
    }
  }
  return undefined;
}

/**
 * Fresh 2 wraps the same handler map in a typed factory so the context type is
 * inferred, which puts the object one call deeper than Fresh 1 leaves it. The map
 * inside is identical, so recognising the wrapper is all that separates a
 * recognised route from an invisible one.
 */
function unwrapDefine(value: ts.Expression): { value: ts.Expression; wrapped: boolean } {
  const call = unwrapExpression(value);
  if (!ts.isCallExpression(call)) return { value: call, wrapped: false };
  if (!isDefineHandlers(expressionName(call.expression))) return { value: call, wrapped: false };
  return { value: call.arguments[0] ?? call, wrapped: true };
}

function isDefineHandlers(callee: string): boolean {
  return callee === "defineHandlers" || /(^|\.)define\.handlers$/.test(callee);
}

/** Does this file really belong to Fresh, rather than merely living under `routes/`? */
function isFresh(file: ParsedFile, typeText: string): boolean {
  if (importsFrom(file, FRESH_MODULES)) return true;
  if (FRESH_TYPE.test(typeText)) return true;
  return allCalls(file).some((call) => isDefineHandlers(expressionName(call.expression)));
}

/**
 * The bindings a Fresh handler receives.
 *
 * Fresh hands over the request and a context, and both are the caller's: the
 * request is what they sent, and `ctx.params` is the part of the URL the route
 * pattern captured. `ctx.state` is what middleware attached — the resolved user,
 * most often — and the taint model already treats a `state` property as
 * server-derived, so seeding the context root does not turn an authenticated
 * subject into attacker data.
 *
 * Fresh 2 hands over one context instead of the pair, so a handler declared
 * inside the typed factory has its request on that single parameter rather than
 * ahead of it. The binding is caller data either way; getting the wording right
 * is what makes the evidence line name something the reader can find in the body.
 *
 * A function taking three or more parameters is not a Fresh handler whatever the
 * module exports it as; the common three-parameter shape is Express middleware,
 * whose second parameter is the response. Seeding that would describe everything
 * the server writes as something the caller chose.
 */
function freshSeeds(fn: ts.Node, singleContext: boolean): TaintSeed[] {
  const parameters = (fn as ts.FunctionLikeDeclaration).parameters;
  if (!parameters || parameters.length === 0 || parameters.length > 2) return [];

  const seeds: TaintSeed[] = [];
  const first = parameters[0];
  if (first && ts.isIdentifier(first.name)) {
    seeds.push({ name: first.name.text, origin: singleContext ? FRESH_CONTEXT_ORIGIN : REQUEST_ORIGIN });
  }
  const second = parameters[1];
  if (second && ts.isIdentifier(second.name)) seeds.push({ name: second.name.text, origin: ROUTE_PARAMS_ORIGIN });
  return seeds;
}

function freshEntryPoints(file: ParsedFile, claimed: Set<ts.Node>): EntryPoint[] {
  const path = freshRoutePath(file.relativePath);
  if (path === null) return [];

  const handler = exportedHandler(file);
  if (!handler) return [];
  if (!isFresh(file, handler.typeText)) return [];

  const defined = handler.value ? unwrapDefine(handler.value) : undefined;
  const object = defined ? unwrapObject(defined.value) : undefined;
  if (object && defined) {
    const found: EntryPoint[] = [];
    for (const property of object.properties) {
      const verb = propertyKey(file, property);
      if (!FRESH_VERBS.has(verb)) continue;
      const fn = memberFunction(file, object, verb);
      if (fn && claimed.has(fn)) continue;
      if (fn) claimed.add(fn);
      found.push(
        entryPoint(file, { method: verb, path }, property, fn, {
          seeds: fn ? freshSeeds(fn, defined.wrapped) : [],
          trusted: []
        })
      );
    }
    return found;
  }

  // A single function answers every verb Fresh routes to the file, which is a
  // fact worth reporting rather than guessing GET: an unguarded write hiding in
  // an `ANY` route is precisely the shape that gets missed in review.
  const fn = handler.fn ?? (handler.value ? functionValue(file, handler.value) : undefined);
  if (fn && claimed.has(fn)) return [];
  if (fn) claimed.add(fn);
  if (!fn && !handler.value) return [];

  return [
    entryPoint(file, { method: "ANY", path }, handler.declaration, fn, {
      seeds: fn ? freshSeeds(fn, defined?.wrapped ?? false) : [],
      trusted: []
    })
  ];
}

/* ------------------------------- the adapter ------------------------------- */

/** Cheap pre-filters, so forty adapters do not each walk every AST. */
const DENO_MENTION = /\bDeno\s*\.\s*serve(?:Http)?\s*[<(]/;
const STD_MENTION = /deno\.land\/std[^"'`]*\/http\/|jsr:@std\/http|["'`]@std\/http/;
const FRESH_MENTION =
  /\$fresh\/|jsr:@fresh\/|["'`]@fresh\/|deno\.land\/x\/fresh|\bHandlers\b|\bFreshContext\b|\bHandlerContext\b|\bRouteContext\b|\bdefine\s*\.\s*handlers\s*\(|\bdefineHandlers\s*\(/;
const EXPORTS_A_HANDLER = /\bexport\s+(?:const|let|var|async\s+function|function)\s+handler\b/;

function applies(file: ParsedFile): boolean {
  const text = file.text;
  // `Deno.serve` is conclusive wherever the file lives: nothing else in the
  // ecosystem is spelled that way.
  if (DENO_MENTION.test(text)) return true;
  if (STD_MENTION.test(text) && /\bserve(?:Tls)?\s*\(/.test(text)) return true;
  // Fresh has to satisfy all three: the route tree, the exported name the
  // framework looks for, and something that ties the file to Fresh rather than to
  // any other project that happens to keep its handlers in `routes/`.
  return freshRoutePath(file.relativePath) !== null && EXPORTS_A_HANDLER.test(text) && FRESH_MENTION.test(text);
}

function detect(file: ParsedFile): EntryPoint[] {
  // One function is one entry point. The shapes below can share a body — a Fresh
  // route module is free to call `Deno.serve` in a script guard — and two claims
  // on one function would report the same handler twice with two sets of seeds,
  // the second of which would be wrong about what the parameters are.
  const claimed = new Set<ts.Node>();
  return [
    ...freshEntryPoints(file, claimed),
    ...serveEntryPoints(file, claimed),
    ...serveHttpEntryPoints(file, claimed)
  ];
}

export const denoAdapter: FrameworkAdapter = { id: "deno", applies, detect };

/**
 * Fresh rides along with the same pass, and is kept named for the registry.
 *
 * A Fresh route file and a `Deno.serve` entry file are the same runtime and can
 * be the same file, so running them as two adapters would let both claim one
 * handler and put it in the report twice. One `detect` with one claimed set is
 * what makes each function belong to exactly one shape. `registerAdapter`
 * deduplicates by id, so registering both of these names registers the pass once.
 */
export const freshAdapter = denoAdapter;
