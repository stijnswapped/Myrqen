import ts from "typescript";
import {
  allCalls,
  functionOf,
  joinRoute,
  parameterNames,
  type EntryPoint,
  type FrameworkAdapter,
  type TaintSeed
} from "../entrypoints.js";
import { calleeTail, collect, literalTextOf } from "../helpers.js";
import { lineOf, type ParsedFile } from "../parse.js";

/* ------------------------------------------------------------------------- *
 * Nitro, Nuxt 3-4 server routes, and h3
 *
 * Two things about this framework family defeat a generic request model, and
 * both of them have to be answered here or the file stays invisible.
 *
 * The first is the address. A Nitro route declares no path anywhere in its
 * source: `server/api/members/search.post.ts` *is* `POST /api/members/search`,
 * and the only place that fact exists is the file name. A scanner that reads
 * the AST alone can see the handler and still have nothing to call it, so every
 * finding inside it is reported against no endpoint — which a reader cannot act
 * on.
 *
 * The second is the input. h3 does not hang the request on properties of an
 * object the way Express does; it hands the handler one opaque `H3Event` and
 * delivers everything the caller sent through free functions that take that
 * event — `getQuery(event)`, `await readBody(event)`, `getRouterParam(event,
 * "id")`. Nothing in `event.something` names the query string, so a model that
 * only follows property access sees a handler that reads nothing at all. The
 * accessor list below is what turns those calls back into caller data, and it
 * is recorded per entry point because `getQuery` means nothing in a file that
 * does not use h3.
 * ------------------------------------------------------------------------- */

/**
 * The h3 free functions that return data the caller chose.
 *
 * Deliberately excluded, because including them would be worse than useless:
 * `getRequestIP`, `useSession`, `getSession` and `requireUserSession` are
 * server-derived. A session identifier is exactly the value a correctly scoped
 * query is *supposed* to be filtered by, so seeding it would make every
 * properly written handler in the repository look like a broken one.
 */
const H3_ACCESSORS = [
  "getQuery",
  "getRouterParam",
  "getRouterParams",
  "readBody",
  "readRawBody",
  "readValidatedBody",
  "readMultipartFormData",
  "readFormData",
  "getHeader",
  "getHeaders",
  "getRequestHeader",
  "getRequestHeaders",
  "getCookie",
  "getRequestURL",
  "getRequestPath",
  "getValidatedQuery",
  "getValidatedRouterParams"
];

/**
 * The wrappers whose first argument is an h3 handler.
 *
 * `defineCachedEventHandler` and its bare alias take the identical shape — a
 * handler function, or an options object with a `handler` property — so a
 * cached route is exactly as reachable, and exactly as tainted, as an uncached
 * one. `defineLazyEventHandler` is left out on purpose: its argument is a
 * *factory* that returns the handler, so treating that argument as the handler
 * would attach the entry point to a function whose parameters are not the
 * event, and a wrong seed is worse than a missing one.
 */
const HANDLER_FACTORIES = new Set([
  "defineEventHandler",
  "eventHandler",
  "defineCachedEventHandler",
  "cachedEventHandler"
]);

/** Cheap pre-filter for the handler wrappers. `<` covers `defineEventHandler<T>(…)`. */
const H3_MENTION = /\b(?:defineEventHandler|eventHandler|defineCachedEventHandler|cachedEventHandler)\s*[<(]/;

/** Any of the ways a module can name a default export, ESM or CommonJS. */
const DEFAULT_EXPORT_MENTION = /\bexport\s+default\b|\bexport\s*=|\bmodule\s*\.\s*exports\b|\bexports\s*\.\s*default\b/;

const SOURCE_EXTENSION = /\.[cm]?[jt]sx?$/;

/** The trailing `.post` in `search.post.ts`, which is where the verb lives. */
const METHOD_SUFFIX = /\.(get|post|put|patch|delete|head|options)$/i;

/** Verbs an h3 router mounts a handler under, when one is used instead of the file tree. */
const ROUTER_VERBS = new Set(["get", "post", "put", "patch", "delete", "head", "options", "use", "all"]);

interface Address {
  method: string;
  path: string;
}

/** A request that has not been placed: the seeds still matter, the label does not. */
const UNPLACED: Address = { method: "ANY", path: "/" };

/**
 * The route a Nitro file name declares, or null when the path is not a route tree.
 *
 * `server/api/**` is served under `/api`, `server/routes/**` at the root, and
 * `server/middleware/**` is not addressable at all — every request passes
 * through it, which is why it is reported as `ANY /`. Bracket segments are kept
 * verbatim: `[id]` is what the developer wrote, what the Nuxt docs call it, and
 * what they will search the report for.
 */
function addressFromPath(relativePath: string): Address | null {
  const parts = relativePath.split("/").filter((part) => part.length > 0);
  const fileName = parts.pop();
  if (!fileName || !SOURCE_EXTENSION.test(fileName)) return null;

  // The last `server` wins, so a monorepo path such as
  // `apps/dashboard/server/api/x.ts` resolves against the app's own tree.
  let root = parts.lastIndexOf("server");
  if (root === -1) root = parts.findIndex((part) => part === ".nuxt" || part === ".nitro" || part === "nitro");
  if (root === -1) return null;

  const inside = parts.slice(root + 1);
  const area = inside[0];
  if (area === "middleware") return { ...UNPLACED };
  if (area !== "api" && area !== "routes") return null;

  const base = fileName.replace(SOURCE_EXTENSION, "");
  const suffix = METHOD_SUFFIX.exec(base);
  // A file with no verb suffix answers every method, which is a fact worth
  // reporting rather than guessing GET: an unguarded write hiding in an
  // `ANY` route is precisely the shape that gets missed in review.
  const method = suffix ? suffix[1]!.toUpperCase() : "ANY";
  const name = suffix ? base.slice(0, base.length - suffix[0].length) : base;

  // `index.get.ts` addresses the directory it sits in rather than a segment of
  // its own, so `server/api/orders/index.get.ts` is `GET /api/orders`.
  const leaf = name === "index" ? [] : [name];
  return { method, path: joinRoute(area === "api" ? "api" : "", ...inside.slice(1), ...leaf) };
}

/** Does this path sit somewhere Nitro turns into a route? */
function isNitroRoutePath(relativePath: string): boolean {
  return addressFromPath(relativePath) !== null;
}

/**
 * The route an h3 router mounts this handler under.
 *
 * `createRouter().get("/orders/:id", defineEventHandler(…))` is the same
 * framework without the file-based convention, and it is how h3 is used outside
 * Nuxt. The literal is only read for the label; nothing about the seeds depends
 * on it, so a computed path costs the address and nothing else.
 */
function addressFromRouter(call: ts.CallExpression): Address | null {
  const parent = call.parent;
  if (!parent || !ts.isCallExpression(parent)) return null;
  if (!parent.arguments.includes(call)) return null;

  const verb = calleeTail(parent).toLowerCase();
  if (!ROUTER_VERBS.has(verb)) return null;

  const first = parent.arguments[0];
  const literal = first ? literalTextOf(first) : null;
  if (!literal || !literal.startsWith("/")) return null;

  return { method: verb === "use" || verb === "all" ? "ANY" : verb.toUpperCase(), path: literal };
}

/** A function declared under this name in this file, when one can be found. */
function localFunction(file: ParsedFile, name: string): ts.Node | undefined {
  for (const declaration of collect(file.source, ts.isVariableDeclaration)) {
    if (!ts.isIdentifier(declaration.name) || declaration.name.text !== name) continue;
    const fn = functionOf(declaration.initializer);
    if (fn) return fn;
  }
  for (const declaration of collect(file.source, ts.isFunctionDeclaration)) {
    if (declaration.name?.text === name) return declaration;
  }
  return undefined;
}

/**
 * The function body a handler wrapper will actually run.
 *
 * The object form exists so a route can attach `onRequest` and
 * `onBeforeResponse` hooks beside its handler; only `handler` receives the
 * request in the sense this analysis cares about. When the handler is a name
 * declared elsewhere in the file it is resolved, and when it is imported it is
 * not — an entry point with no body is still worth emitting for the address.
 */
function handlerOf(file: ParsedFile, call: ts.CallExpression): ts.Node | undefined {
  const first = call.arguments[0];
  if (!first) return undefined;

  const direct = functionOf(first);
  if (direct) return direct;
  if (ts.isIdentifier(first)) return localFunction(file, first.text);
  if (!ts.isObjectLiteralExpression(first)) return undefined;

  for (const property of first.properties) {
    const name = property.name ? property.name.getText(file.source).replace(/["']/g, "") : "";
    if (name !== "handler") continue;
    if (ts.isMethodDeclaration(property)) return property;
    if (ts.isShorthandPropertyAssignment(property)) return localFunction(file, property.name.text);
    if (!ts.isPropertyAssignment(property)) continue;
    const value = functionOf(property.initializer);
    if (value) return value;
    if (ts.isIdentifier(property.initializer)) return localFunction(file, property.initializer.text);
  }
  return undefined;
}

/**
 * The event parameter, named so the analyser can follow it.
 *
 * Only a plain identifier is seeded. A destructured parameter would need the
 * bound names rather than the event, and guessing which of them holds caller
 * data is the kind of guess that manufactures a false positive in every rule at
 * once, so an unusual signature yields an entry point with no seeds instead.
 */
function seedsFor(fn: ts.Node | undefined): TaintSeed[] {
  const first = parameterNames(fn)[0];
  if (!first) return [];
  return [{ name: first, origin: "event (inbound request)" }];
}

function entryPointAt(file: ParsedFile, address: Address, at: ts.Node, fn: ts.Node | undefined): EntryPoint {
  const seeds = seedsFor(fn);
  return {
    framework: "nitro",
    kind: "http",
    method: address.method,
    path: address.path,
    line: lineOf(file, at),
    // A fresh array per entry point: these are handed to rules that may hold on
    // to them, and one shared instance would let any of them edit every route's
    // idea of what an accessor is.
    accessorFunctions: [...H3_ACCESSORS],
    ...(fn ? { node: fn } : {}),
    ...(seeds.length > 0 ? { seeds } : {})
  };
}

/** The function a module exports as its default, in either module system. */
function defaultExportedFunction(file: ParsedFile): ts.Node | undefined {
  for (const statement of file.source.statements) {
    if (ts.isExportAssignment(statement)) {
      const fn = functionOf(statement.expression);
      if (fn) return fn;
      if (ts.isIdentifier(statement.expression)) return localFunction(file, statement.expression.text);
      continue;
    }
    if (ts.isFunctionDeclaration(statement) && hasDefaultModifier(statement)) return statement;
    if (!ts.isExpressionStatement(statement) || !ts.isBinaryExpression(statement.expression)) continue;

    const assignment = statement.expression;
    if (assignment.operatorToken.kind !== ts.SyntaxKind.EqualsToken) continue;
    const target = assignment.left.getText(file.source).replace(/\s+/g, "");
    if (target !== "module.exports" && target !== "exports.default") continue;
    const fn = functionOf(assignment.right);
    if (fn) return fn;
    if (ts.isIdentifier(assignment.right)) return localFunction(file, assignment.right.text);
  }
  return undefined;
}

function hasDefaultModifier(node: ts.FunctionDeclaration): boolean {
  return Boolean(node.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.DefaultKeyword));
}

/**
 * Is this bare exported function really an h3 handler?
 *
 * A directory called `server/api` is not proof on its own — a repository that
 * has nothing to do with Nuxt can hold `server/api/client.ts` exporting
 * `createClient(options)`, and seeding `options` there would put attacker
 * control on a configuration object. Nitro's own convention answers it: the
 * parameter is called `event`, or it is typed `H3Event`. Anything else gets the
 * route label and no seeds, which loses coverage without inventing flows.
 */
function looksLikeEventParameter(file: ParsedFile, fn: ts.Node): boolean {
  const parameter = (fn as ts.FunctionLikeDeclaration).parameters?.[0];
  if (!parameter) return false;
  if (ts.isIdentifier(parameter.name) && parameter.name.text === "event") return true;
  return Boolean(parameter.type && /\bH3Event\b/.test(parameter.type.getText(file.source)));
}

function applies(file: ParsedFile): boolean {
  // A handler wrapper is conclusive wherever the file lives, so an h3 server
  // written outside a `server/` tree is still recognised.
  if (H3_MENTION.test(file.text)) return true;
  // Otherwise the file has to both sit in a route tree and export something to
  // serve. `server/utils/db.ts` satisfies neither and must not be claimed.
  return isNitroRoutePath(file.relativePath) && DEFAULT_EXPORT_MENTION.test(file.text);
}

function detect(file: ParsedFile): EntryPoint[] {
  const fromPath = addressFromPath(file.relativePath);
  const found: EntryPoint[] = [];

  for (const call of allCalls(file)) {
    if (!HANDLER_FACTORIES.has(calleeTail(call))) continue;
    // File-based routing is the contract in a Nitro tree, so the file name wins
    // there; a router literal is only consulted for handlers that sit outside
    // one. A handler that is neither placed by its path nor mounted at a
    // literal still becomes an entry point at `/`, because the seeds are the
    // half of this that the data-flow rules cannot do without.
    const address = fromPath ?? addressFromRouter(call) ?? UNPLACED;
    found.push(entryPointAt(file, address, call, handlerOf(file, call)));
  }

  if (found.length > 0) return found;
  if (!fromPath) return [];

  // Nitro also accepts a bare function as the default export, and a route
  // written that way is served identically to a wrapped one.
  const fn = defaultExportedFunction(file);
  if (!fn) return [];
  if (parameterNames(fn).length !== 1) return [];
  if (!looksLikeEventParameter(file, fn)) {
    return [{ framework: "nitro", kind: "http", method: fromPath.method, path: fromPath.path, line: lineOf(file, fn), node: fn }];
  }
  return [entryPointAt(file, fromPath, fn, fn)];
}

export const nitroAdapter: FrameworkAdapter = { id: "nitro", applies, detect };
