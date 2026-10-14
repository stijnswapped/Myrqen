import ts from "typescript";
import { collect, expressionName, literalTextOf } from "../helpers.js";
import { lineOf, type ParsedFile } from "../parse.js";
import {
  functionOf,
  importsFrom,
  parameterNames,
  type EntryPoint,
  type FrameworkAdapter,
  type TaintSeed
} from "../entrypoints.js";

/* ------------------------------------------------------------------------- *
 * Bun's HTTP and WebSocket surface
 *
 * A Bun server registers nothing. There is no `app.get("/x", handler)` for route
 * discovery to find and no conventional file tree to read an address out of —
 * the whole server is one object literal handed to `Bun.serve`, and the handler
 * inside it is an ordinary method whose parameter happens to be a `Request`. The
 * engine's parameter-name model does recognise a parameter called `request`, but
 * it recognises nothing at all when the same handler is written `fetch(req)`
 * under a `routes` key, and it never learns that the *second* parameter is Bun's
 * own `Server` rather than anything a caller sent. Without an entry point the
 * file has no request parameter, without a request parameter it has no taint, and
 * every data-flow rule in the engine stays silent over a handler that resolves a
 * filesystem path straight out of `request.url`.
 *
 * The `routes` object is the half of this worth the most. It is the one place in
 * the Bun API where the source states its own address, and it states it in Bun's
 * own syntax — `/api/users/:id`, `/assets/*`. Those are kept exactly as written:
 * `:id` is what the developer typed, what the Bun documentation calls it, and
 * what they will search the report for. A bare `fetch` is the opposite case: it
 * answers every request that no route matched, so it is reported as `ANY /` and
 * the generic dispatch discovery in `routes.ts` supplies the specific paths the
 * handler branches on.
 * ------------------------------------------------------------------------- */

const FRAMEWORK = "bun";

/** How a `Request` is described in evidence, whatever the parameter is called. */
const REQUEST_ORIGIN = "request (inbound request)";

/** How a WebSocket frame is described in evidence. */
const MESSAGE_ORIGIN = "message (payload sent by the connected client)";

/**
 * Verbs Bun routes a method-keyed `routes` entry under.
 *
 * Bun's own documentation writes them upper-case, and the key is compared
 * case-insensitively so a handler written `get:` still yields its seeds. Matching
 * the other case costs nothing here — the object is already known to be a route
 * table — and refusing it would lose a certain seed over a spelling.
 */
const ROUTE_VERBS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]);

/**
 * Keys that only ever appear in a `Bun.serve` configuration.
 *
 * Used solely to settle the bare `export default { fetch }` shape, where the
 * object could as easily be a module exporting a `fetch` wrapper. Nothing else in
 * this adapter needs them, because `Bun.serve(...)` says what the object is.
 */
const SERVE_OPTION_KEYS = new Set([
  "port",
  "hostname",
  "unix",
  "routes",
  "static",
  "websocket",
  "error",
  "development",
  "tls",
  "idleTimeout",
  "maxRequestBodySize",
  "reusePort",
  "id"
]);

/** Parameter names and annotations that make a `fetch` member a server's, not a wrapper's. */
const REQUEST_PARAMETER = /^(request|req)$/;

/* ------------------------------ AST plumbing ------------------------------ */

/** An expression seen through the wrappers that change nothing at runtime. */
function unwrap(node: ts.Expression | undefined): ts.Expression | undefined {
  let current = node;
  for (let depth = 0; current && depth < 4; depth += 1) {
    if (
      ts.isAsExpression(current) ||
      ts.isSatisfiesExpression(current) ||
      ts.isParenthesizedExpression(current) ||
      ts.isNonNullExpression(current)
    ) {
      current = current.expression;
      continue;
    }
    return current;
  }
  return current;
}

/** The initialiser of a variable declared under this name anywhere in the file. */
function localValue(file: ParsedFile, name: string): ts.Expression | undefined {
  for (const declaration of collect(file.source, ts.isVariableDeclaration)) {
    if (!ts.isIdentifier(declaration.name) || declaration.name.text !== name) continue;
    if (declaration.initializer) return declaration.initializer;
  }
  return undefined;
}

/** A function declared or bound under this name in this file, when one exists. */
function localFunction(file: ParsedFile, name: string): ts.Node | undefined {
  for (const declaration of collect(file.source, ts.isFunctionDeclaration)) {
    if (declaration.name?.text === name && declaration.body) return declaration;
  }
  const value = localValue(file, name);
  return value ? functionOf(unwrap(value)) : undefined;
}

/**
 * The object literal a value stands for, following one name declared in this
 * file. `Bun.serve(config)` with the options hoisted into a `const` above is
 * ordinary in a server that reloads itself, and it is the whole configuration.
 */
function objectLiteralOf(file: ParsedFile, node: ts.Expression | undefined): ts.ObjectLiteralExpression | undefined {
  const value = unwrap(node);
  if (!value) return undefined;
  if (ts.isObjectLiteralExpression(value)) return value;
  if (!ts.isIdentifier(value)) return undefined;
  const resolved = unwrap(localValue(file, value.text));
  return resolved && ts.isObjectLiteralExpression(resolved) ? resolved : undefined;
}

function propertyKey(file: ParsedFile, property: ts.ObjectLiteralElementLike): string {
  if (!property.name) return "";
  if (ts.isIdentifier(property.name) || ts.isStringLiteralLike(property.name)) return property.name.text;
  return property.name.getText(file.source).replace(/["'`]/g, "");
}

/** The member of an object literal under this key, in whichever form it was written. */
function member(
  file: ParsedFile,
  object: ts.ObjectLiteralExpression,
  key: string
): ts.ObjectLiteralElementLike | undefined {
  return object.properties.find((property) => propertyKey(file, property) === key);
}

/** The nested object literal one member holds, following a name declared in this file. */
function memberObject(
  file: ParsedFile,
  object: ts.ObjectLiteralExpression,
  key: string
): ts.ObjectLiteralExpression | undefined {
  const property = member(file, object, key);
  if (!property) return undefined;
  if (ts.isPropertyAssignment(property)) return objectLiteralOf(file, property.initializer);
  if (ts.isShorthandPropertyAssignment(property)) return objectLiteralOf(file, property.name);
  return undefined;
}

/**
 * The function a member holds.
 *
 * All four spellings occur in real servers: the method shorthand Bun's own
 * documentation uses, an arrow assigned to the key, a shorthand naming a function
 * declared above, and a key pointing at one. A member whose value is imported
 * resolves to nothing here, which costs the seeds and not the address.
 */
function memberFunction(file: ParsedFile, property: ts.ObjectLiteralElementLike | undefined): ts.Node | undefined {
  if (!property) return undefined;
  if (ts.isMethodDeclaration(property) && property.body) return property;
  if (ts.isShorthandPropertyAssignment(property)) return localFunction(file, property.name.text);
  if (!ts.isPropertyAssignment(property)) return undefined;
  const value = unwrap(property.initializer);
  if (!value) return undefined;
  return functionOf(value) ?? (ts.isIdentifier(value) ? localFunction(file, value.text) : undefined);
}

/* --------------------------------- Seeds --------------------------------- */

/**
 * The request parameter, named so the taint model can follow it.
 *
 * Only a plain identifier is seeded. A `Request` has no destructuring form that
 * means anything to Bun, so a bound pattern in that position is somebody's own
 * convention and guessing which of its names holds caller data is exactly the
 * invention that turns one wrong claim into a false positive in every rule at
 * once.
 */
function requestSeed(fn: ts.Node | undefined, origin: string, index = 0): TaintSeed[] {
  const parameter = (fn as ts.FunctionLikeDeclaration | undefined)?.parameters?.[index];
  if (!parameter || !ts.isIdentifier(parameter.name)) return [];
  return [{ name: parameter.name.text, origin }];
}

/** Parameter names at the given positions, for the arguments Bun supplies itself. */
function trustedAt(fn: ts.Node | undefined, ...indices: number[]): string[] {
  const names = parameterNames(fn);
  return indices.map((index) => names[index]).filter((name): name is string => Boolean(name));
}

/**
 * One HTTP entry point.
 *
 * The second parameter of every Bun request handler is the `Server` — the object
 * that owns `upgrade`, `publish`, `stop` and the client's resolved address. It is
 * the runtime's, not the caller's, and it is named `server` often enough that
 * leaving it unnamed would be a live risk the day the generic model learns that
 * name.
 */
function httpEntry(file: ParsedFile, at: ts.Node, fn: ts.Node | undefined, method: string, path: string): EntryPoint {
  const seeds = requestSeed(fn, REQUEST_ORIGIN);
  const trusted = trustedAt(fn, 1);
  return {
    framework: FRAMEWORK,
    kind: "http",
    method,
    path,
    line: lineOf(file, at),
    ...(fn ? { node: fn } : {}),
    ...(seeds.length > 0 ? { seeds } : {}),
    ...(fn && trusted.length > 0 ? { trustedParameters: trusted } : {})
  };
}

/* ------------------------- The configuration object ------------------------- */

/**
 * `routes`, which is the only part of a Bun server that knows its own address.
 *
 * Three value shapes are documented and all three appear in real code: a bare
 * handler that answers every verb, an object mapping verbs to handlers, and a
 * pre-built `Response` for a static asset. The third is deliberately not emitted
 * — it holds no function, reads nothing the caller sent, and announcing it would
 * put a route in the report that no rule can ever have anything to say about.
 */
function routeEntries(file: ParsedFile, routes: ts.ObjectLiteralExpression): EntryPoint[] {
  const entries: EntryPoint[] = [];

  for (const property of routes.properties) {
    const path = propertyKey(file, property);
    // Bun matches on a path, so a key that is not one is not a route. `:id` and
    // `*` are kept verbatim: they are Bun's own syntax and the reader's own words.
    if (!path.startsWith("/")) continue;

    const handler = memberFunction(file, property);
    if (handler) {
      entries.push(httpEntry(file, property, handler, "ANY", path));
      continue;
    }

    const value = ts.isPropertyAssignment(property) ? unwrap(property.initializer) : undefined;
    if (value && isStaticResponse(value)) continue;

    const byVerb = value ? objectLiteralOf(file, value) : undefined;
    if (!byVerb) {
      // A handler this file cannot resolve — imported, or built by a factory — is
      // still a reachable address, and the address is the half of a route entry
      // that no other part of the engine can recover.
      entries.push(httpEntry(file, property, undefined, "ANY", path));
      continue;
    }

    for (const verbProperty of byVerb.properties) {
      const verb = propertyKey(file, verbProperty).toUpperCase();
      if (!ROUTE_VERBS.has(verb)) continue;
      const verbHandler = memberFunction(file, verbProperty);
      if (!verbHandler && ts.isPropertyAssignment(verbProperty) && isStaticResponse(verbProperty.initializer)) continue;
      entries.push(httpEntry(file, verbProperty, verbHandler, verb, path));
    }
  }

  return entries;
}

/** A canned answer rather than a handler: `new Response(...)`, `Response.json(...)`. */
function isStaticResponse(node: ts.Expression): boolean {
  const value = unwrap(node);
  if (!value) return false;
  if (ts.isNewExpression(value)) return expressionName(value.expression) === "Response";
  if (ts.isCallExpression(value)) return /^Response\./.test(expressionName(value.expression));
  return false;
}

/**
 * `websocket.message`, the one WebSocket callback that carries caller data.
 *
 * `open`, `close` and `drain` receive the socket and the runtime's own close
 * codes; only `message` receives a frame the connected client composed. The first
 * parameter is Bun's `ServerWebSocket` — it carries `data`, which is the state
 * *the server* attached at upgrade time, so treating it as attacker data would
 * make every correctly scoped subscription look like a defect.
 *
 * An unresolvable handler yields nothing here, unlike a route: the address of a
 * WebSocket callback is a constant, so an entry point without a body would add a
 * labelled endpoint to the report carrying neither an address nor anything to
 * analyse.
 */
function websocketEntries(file: ParsedFile, websocket: ts.ObjectLiteralExpression): EntryPoint[] {
  const handler = memberFunction(file, member(file, websocket, "message"));
  if (!handler) return [];

  const seeds = requestSeed(handler, MESSAGE_ORIGIN, 1);
  const trusted = trustedAt(handler, 0);
  return [
    {
      framework: FRAMEWORK,
      kind: "ipc",
      method: "MESSAGE",
      path: "websocket",
      line: lineOf(file, handler),
      node: handler,
      ...(seeds.length > 0 ? { seeds } : {}),
      ...(trusted.length > 0 ? { trustedParameters: trusted } : {})
    }
  ];
}

/**
 * Every entry point one server configuration declares.
 *
 * `error` is not among them, and that is a decision rather than an omission: its
 * parameter is the exception the server just caught. It is server-derived, and
 * seeding it would put attacker control on whatever a failing database driver
 * happened to throw — a flow that exists in no request.
 */
function configEntries(file: ParsedFile, config: ts.ObjectLiteralExpression): EntryPoint[] {
  const entries: EntryPoint[] = [];

  const fetchProperty = member(file, config, "fetch");
  if (fetchProperty) {
    // `fetch` answers everything no route matched, so it has no address of its
    // own. `ANY /` says that honestly, and the hand-rolled dispatch discovery
    // recovers the paths the body actually branches on.
    entries.push(httpEntry(file, fetchProperty, memberFunction(file, fetchProperty), "ANY", "/"));
  }

  const routes = memberObject(file, config, "routes");
  if (routes) entries.push(...routeEntries(file, routes));

  const websocket = memberObject(file, config, "websocket");
  if (websocket) entries.push(...websocketEntries(file, websocket));

  return entries;
}

/* ------------------------------ Finding servers ------------------------------ */

/**
 * Local names bound to Bun's own `serve`.
 *
 * `import { serve } from "bun"` is the form the documentation uses for a server
 * started from a module, and a file written that way never mentions the `Bun`
 * global at all — so keying only on `Bun.serve` would miss it entirely. The
 * require and namespace forms are here for the same reason the rest of this
 * engine handles them: a great deal of the Node-shaped code in the world is still
 * written that way.
 */
function serveNames(file: ParsedFile): Set<string> {
  const names = new Set<string>();

  for (const statement of file.source.statements) {
    if (!ts.isImportDeclaration(statement)) continue;
    if (!ts.isStringLiteralLike(statement.moduleSpecifier) || statement.moduleSpecifier.text !== "bun") continue;
    const clause = statement.importClause;
    if (!clause) continue;
    if (clause.name) names.add(`${clause.name.text}.serve`);
    const bindings = clause.namedBindings;
    if (!bindings) continue;
    if (ts.isNamespaceImport(bindings)) {
      names.add(`${bindings.name.text}.serve`);
      continue;
    }
    for (const element of bindings.elements) {
      if ((element.propertyName ?? element.name).text === "serve") names.add(element.name.text);
    }
  }

  for (const declaration of collect(file.source, ts.isVariableDeclaration)) {
    const initializer = unwrap(declaration.initializer);
    if (!initializer || !ts.isCallExpression(initializer)) continue;
    if (expressionName(initializer.expression) !== "require") continue;
    const first = initializer.arguments[0];
    if (!first || literalTextOf(first) !== "bun") continue;
    if (ts.isIdentifier(declaration.name)) {
      names.add(`${declaration.name.text}.serve`);
      continue;
    }
    if (!ts.isObjectBindingPattern(declaration.name)) continue;
    for (const element of declaration.name.elements) {
      const source = element.propertyName ?? element.name;
      if (ts.isIdentifier(source) && source.text === "serve" && ts.isIdentifier(element.name)) {
        names.add(element.name.text);
      }
    }
  }

  return names;
}

/** Is this call the one that starts a Bun server? */
function isServeCall(call: ts.CallExpression, names: Set<string>): boolean {
  const callee = expressionName(call.expression);
  if (callee === "Bun.serve" || callee.endsWith(".Bun.serve")) return true;
  return names.has(callee);
}

/**
 * Does this file work with Bun's own runtime at all?
 *
 * Required before a bare `export default { fetch }` is claimed, because that
 * object is also how a Cloudflare Worker and a Deno server are written, and their
 * own adapters describe them with the trusted parameters their runtimes actually
 * pass. Checked through the AST rather than the text so a mention in a comment
 * cannot stand in for a dependency.
 */
function usesBun(file: ParsedFile): boolean {
  if (importsFrom(file, /^bun$|^bun:/)) return true;
  for (const access of collect(file.source, ts.isPropertyAccessExpression)) {
    if (ts.isIdentifier(access.expression) && access.expression.text === "Bun") return true;
  }
  // `await import("bun:sqlite")` is the same dependency deferred, and a server
  // that opens its database lazily is written exactly that way.
  for (const call of collect(file.source, ts.isCallExpression)) {
    if (call.expression.kind !== ts.SyntaxKind.ImportKeyword) continue;
    const first = call.arguments[0];
    if (first && /^bun$|^bun:/.test(literalTextOf(first) ?? "")) return true;
  }
  return false;
}

/**
 * Is this object literal a server rather than a module that happens to export a
 * function called `fetch`?
 *
 * `export default { fetch }` is Bun's shorthand for `Bun.serve`, and it is also
 * exactly what a module wrapping the global `fetch` looks like. Seeding the first
 * parameter of a fetch *wrapper* would announce the caller controls a URL the
 * application chose, so the object has to carry another `Bun.serve` option, or
 * its handler has to take something that is recognisably a `Request`.
 */
function looksLikeServer(file: ParsedFile, config: ts.ObjectLiteralExpression): boolean {
  for (const property of config.properties) {
    if (SERVE_OPTION_KEYS.has(propertyKey(file, property))) return true;
  }
  const handler = memberFunction(file, member(file, config, "fetch"));
  const parameter = (handler as ts.FunctionLikeDeclaration | undefined)?.parameters?.[0];
  if (!parameter) return false;
  if (ts.isIdentifier(parameter.name) && REQUEST_PARAMETER.test(parameter.name.text)) return true;
  // `BunRequest<"/orders/:id">` is what Bun annotates a typed handler with, so the
  // suffix rather than the whole word is what has to match.
  return Boolean(parameter.type && /Request\b/.test(parameter.type.getText(file.source)));
}

/** The object a module hands to the runtime as its default export, in either module system. */
function defaultExportedConfig(file: ParsedFile): ts.ObjectLiteralExpression | undefined {
  for (const statement of file.source.statements) {
    if (ts.isExportAssignment(statement) && !statement.isExportEquals) {
      const object = objectLiteralOf(file, statement.expression);
      if (object) return object;
      continue;
    }
    if (!ts.isExpressionStatement(statement) || !ts.isBinaryExpression(statement.expression)) continue;
    const assignment = statement.expression;
    if (assignment.operatorToken.kind !== ts.SyntaxKind.EqualsToken) continue;
    const target = expressionName(assignment.left);
    if (target !== "module.exports" && target !== "exports") continue;
    const object = objectLiteralOf(file, assignment.right);
    if (object) return object;
  }
  return undefined;
}

/* ------------------------------- The adapter ------------------------------- */

/**
 * The text pre-check.
 *
 * `Bun.serve(` is conclusive on its own. Every other clause needs a Bun
 * dependency *and* a server shape, because `serve(` alone belongs to a dozen
 * libraries and `export default {` with a `fetch` member belongs to two other
 * runtimes. The `serve` clause is deliberately loose about how the call is
 * spelled — an import can rename it to anything, and the local name is the only
 * thing the call site shows — so a file that imports `"bun"` and says `serve`
 * anywhere is walked. `detect` re-checks every one of these against the AST, so a
 * mention inside a comment costs one wasted walk and claims nothing.
 */
function applies(file: ParsedFile): boolean {
  const text = file.text;
  if (/\bBun\s*\.\s*serve\s*[(<]/.test(text)) return true;

  const bunModule = /["']bun["']/.test(text);
  if (!bunModule && !/["']bun:[a-z]/.test(text) && !/\bBun\s*\.\s*[A-Za-z$_]/.test(text)) return false;
  if (bunModule && /\bserve\b/.test(text)) return true;
  if (/\bserve\s*[(<]/.test(text)) return true;
  /*
   * A route table declared without a server, for a `Bun.serve` in another module.
   * The pre-check is a path-shaped key mapping to an object, which is what a route
   * table looks like from a distance; `isRouteTable` in `detect` decides properly.
   */
  if (/["'`]\/[^"'`]*["'`]\s*:\s*\{/.test(text)) return true;
  return /\bexport\s+default\s*\{|\bmodule\s*\.\s*exports\s*=\s*\{/.test(text) && /\bfetch\s*[(:]/.test(text);
}

function detect(file: ParsedFile): EntryPoint[] {
  const names = serveNames(file);
  const entries: EntryPoint[] = [];
  // One configuration object is one server. `Bun.serve(config)` beside `export
  // default config` is the same object read twice, and announcing it twice would
  // put every one of its routes in the report a second time.
  const seen = new Set<ts.ObjectLiteralExpression>();
  const servers = new Set<string>();

  const claim = (config: ts.ObjectLiteralExpression | undefined): void => {
    if (!config || seen.has(config)) return;
    seen.add(config);
    entries.push(...configEntries(file, config));
  };

  for (const call of collect(file.source, ts.isCallExpression)) {
    if (!isServeCall(call, names)) continue;
    claim(objectLiteralOf(file, call.arguments[0]));
    // `const server = Bun.serve(...)` names the handle a hot-reloading server
    // later hands a replacement configuration to.
    const declaration = call.parent;
    if (declaration && ts.isVariableDeclaration(declaration) && ts.isIdentifier(declaration.name)) {
      servers.add(declaration.name.text);
    }
  }

  // `server.reload({ fetch })` swaps the handler of a running server, so its
  // configuration is as reachable as the one `serve` was started with. The
  // receiver has to be a server this file created, or `reload` is any other
  // object's method.
  for (const call of collect(file.source, ts.isCallExpression)) {
    if (!ts.isPropertyAccessExpression(call.expression) || call.expression.name.text !== "reload") continue;
    const receiver = call.expression.expression;
    if (!ts.isIdentifier(receiver) || !servers.has(receiver.text)) continue;
    claim(objectLiteralOf(file, call.arguments[0]));
  }

  // The default-export server is only consulted when nothing started a server
  // explicitly. A file that already calls `serve` has said what it runs, and a
  // `fetch` it also exports is far likelier to be a helper than a second server.
  if (entries.length === 0 && usesBun(file)) {
    const config = defaultExportedConfig(file);
    if (config && member(file, config, "fetch") && looksLikeServer(file, config)) claim(config);
  }

  /*
   * A route table declared on its own, for a `Bun.serve` in another module.
   *
   * `export const reportingRoutes = { "/api/wallets/:walletId/transactions": { GET: … } }`
   * is how a Bun service of any size is written — the routes live with the domain and
   * one entry file assembles them. `routes` was only ever read as a member of a
   * `Bun.serve` configuration, so a handler in such a module had no entry point and no
   * address: a held-out corpus carried exactly this shape and its SQL injection was
   * found at the right line with `route: null`, which the scorer could not match.
   *
   * The shape has to earn it, because an exported object with slash-shaped keys could
   * be a lookup table of anything. Required: every key is a path, and at least one
   * value is an object keyed by HTTP verbs holding functions. That is a route table
   * and very little else is.
   */
  if (entries.length === 0) {
    for (const declaration of collect(file.source, ts.isVariableDeclaration)) {
      if (!ts.isIdentifier(declaration.name) || !declaration.initializer) continue;
      const table = objectLiteralOf(file, declaration.initializer);
      if (!table || seen.has(table) || !isRouteTable(file, table)) continue;
      seen.add(table);
      entries.push(...routeEntries(file, table));
    }
  }

  return entries;
}

/** Every key a path, and at least one value a verb-keyed map of handlers. */
function isRouteTable(file: ParsedFile, table: ts.ObjectLiteralExpression): boolean {
  if (table.properties.length === 0) return false;
  const VERBS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]);
  let verbKeyed = false;

  for (const property of table.properties) {
    const key = propertyKey(file, property);
    if (!key.startsWith("/")) return false;
    const value = ts.isPropertyAssignment(property) ? objectLiteralOf(file, property.initializer) : undefined;
    if (!value) continue;
    for (const inner of value.properties) {
      const verb = propertyKey(file, inner).toUpperCase();
      if (!VERBS.has(verb)) continue;
      if (memberFunction(file, inner)) verbKeyed = true;
    }
  }
  return verbKeyed;
}

export const bunAdapter: FrameworkAdapter = { id: FRAMEWORK, applies, detect };
