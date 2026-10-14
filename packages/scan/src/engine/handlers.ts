/**
 * Request handlers, by position rather than by name.
 *
 * The taint model recognises a request parameter by what it is *called* — `req`,
 * `request`, `ctx`, `c` — or by what an adapter declared. Both miss the commonest way an
 * application is actually assembled: a handler passed to a router by reference, written in
 * another module, whose first parameter is called whatever its author liked. And the name
 * heuristic over-reaches in the other direction: a CLI adapter's `context` parameter is not
 * a request, and following it through a program's helpers reports the program.
 *
 * So the framework's own contract decides: the function handed to `router.get(path, …)` is
 * called with the request first, whatever its parameters are named, wherever it is
 * declared. Recognised:
 *
 *  - Express, Router, Koa-router, Hono and Fastify shorthand registrations —
 *    `x.get|post|put|patch|delete|options|head|all(path, …middleware, handler)` — with
 *    inline, local, imported, member (`controller.show`) and wrapped
 *    (`asyncHandler(fn)`) handlers, `x.route(path).get(handler)` chains, and Fastify's
 *    `x.route({ method, url, handler, preHandler })`;
 *  - router-level middleware registered with `x.use(fn)` ahead of the routes it guards;
 *  - `http.createServer(handler)` / `https.createServer(handler)`;
 *  - Next.js App Router route handlers (`GET`/`POST`… exported from `route.ts`, including
 *    wrapped exports such as `export const POST = withAuth(async (req) => …)`), whose
 *    second parameter carries the route params;
 *  - Next.js pages API routes (the default export under `pages/api`).
 *
 * NestJS controllers, server actions, tRPC procedures and the other architectures the
 * adapters in `ast/frameworks/` know are already entry points; this module does not
 * duplicate them, and `isRequestHandler` answers yes for those too.
 *
 * Each handler also carries the middleware registered in front of it, classified as
 * authenticating or authorising where its name or its body says so, which is what an
 * authorization-coverage rule needs and what a handler body alone cannot show.
 */
import ts from "typescript";
import type { ParsedFile } from "../ast/parse.js";
import { entryPointForFunction } from "../ast/entrypoints.js";
import { calleeTail, expressionName } from "../ast/helpers.js";
import { isCallableBody } from "./callgraph.js";
import type { Definition, ModuleGraph } from "./modules.js";

export interface MiddlewareRef {
  /** The expression as written in the registration. */
  expression: ts.Expression;
  /** Its dotted name, or `""` for an inline function. */
  name: string;
  /** The function it resolves to, when this scan can read it. */
  fn: ts.FunctionLikeDeclaration | null;
  file: ParsedFile | null;
  /** Establishes who the caller is: a session, a token, a signed request. */
  authenticates: boolean;
  /** Decides what the caller may do: a role, a permission, a policy. */
  authorizes: boolean;
}

export interface RequestHandler {
  /** The file the handler function is declared in. */
  file: ParsedFile;
  /** The file the registration is written in. */
  registeredIn: ParsedFile;
  fn: ts.FunctionLikeDeclaration;
  framework: string;
  /** HTTP verb, or `ANY` for middleware and catch-all servers. */
  method: string;
  /** Path as the registration spells it, or null when it has none. */
  path: string | null;
  line: number;
  /** Parameter positions holding caller data: the request object, a route context. */
  requestParameters: number[];
  /** Middleware in front of this handler, in order, router-level `use` first. */
  middleware: MiddlewareRef[];
  /** True when the handler is itself registered as middleware (`x.use(fn)`). */
  isMiddleware: boolean;
}

const VERBS = new Set(["get", "post", "put", "patch", "delete", "options", "head", "all"]);
/** Receivers that are never a router, however the call is shaped. */
const NOT_A_ROUTER =
  /^(res|reply|response|ctx|context|c|req|request|console|logger|log|db|database|pool|client|store|cache|redis|fs|path|crypto|JSON|Object|Array|Math|process|window|document|localStorage|headers|cookies|params|query|url|map|set|list|items|rows|axios|http|https|fetch|api|got|ky|superagent|supertest|request|cy|page|browser)$/i;
const NEXT_VERBS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]);

/** Middleware names that establish identity. Deliberately words, not fragments. */
const AUTHENTICATES =
  /(^|\.)(authenticate\w*|requireAuth\w*|requireUser|requireLogin|requireSession|requireSignedIn|ensureAuth\w*|ensureLoggedIn|isAuthenticated|isLoggedIn|isSignedIn|verifyToken|verifyJwt|verifyJWT|checkJwt|validateToken|jwtAuth|withAuth|protect|protected|auth|authed|authorize\w*|sessionRequired|loginRequired|apiKey\w*|requireApiKey|clerkMiddleware|requireAdmin|requireRole|requireRoles|requirePermission\w*|requireScope\w*|hasRole|checkRole|checkPermission\w*|can|guard|policy)$/i;
/** Middleware names that make an authorisation decision. */
const AUTHORIZES =
  /(^|\.)(authorize\w*|requireAdmin|requireRole|requireRoles|requirePermission\w*|requireScope\w*|hasRole|checkRole|checkPermission\w*|can|guard|policy|isAdmin|adminOnly|requireOwner\w*|requireMember\w*)$/i;

function unwrap(node: ts.Node): ts.Node {
  let current = node;
  for (let depth = 0; depth < 6; depth += 1) {
    if (ts.isParenthesizedExpression(current) || ts.isAsExpression(current) || ts.isSatisfiesExpression(current) || ts.isNonNullExpression(current)) {
      current = current.expression;
      continue;
    }
    return current;
  }
  return current;
}

function stringLiteral(node: ts.Node | undefined): string | null {
  if (!node) return null;
  const bare = unwrap(node);
  return ts.isStringLiteralLike(bare) ? bare.text : null;
}

function lineOf(file: ParsedFile, node: ts.Node): number {
  return file.source.getLineAndCharacterOfPosition(node.getStart(file.source)).line + 1;
}

/** Does the middleware's body refuse a request without a credential? */
function bodyAuthenticates(fn: ts.FunctionLikeDeclaration): boolean {
  if (!fn.body) return false;
  const text = fn.body.getText();
  const refuses = /\b(401|403)\b|Unauthori[sz]ed|Forbidden/.test(text);
  const reads = /\b(authorization|cookie|session|token|jwt|bearer|apiKey|api_key|x-api-key|signature)\b/i.test(text);
  return refuses && reads;
}

function bodyAuthorizes(fn: ts.FunctionLikeDeclaration): boolean {
  if (!fn.body) return false;
  const text = fn.body.getText();
  return /\b403\b|Forbidden/.test(text) && /\b(role|roles|permission|permissions|scope|scopes|isAdmin|admin)\b/.test(text);
}

/**
 * The function an argument of a registration denotes, and what to call it.
 *
 * `fn`, `controller.show`, `asyncHandler(async (req, res) => …)`, `require("./x").handler`.
 * A call wrapping a function literal is the wrapper pattern every Express codebase grows;
 * the literal is the handler. A call that wraps nothing readable — `validate(schema)` — is
 * middleware the scan cannot see into, and is recorded by name.
 */
function functionArgument(
  graph: ModuleGraph,
  file: ParsedFile,
  argument: ts.Expression
): { fn: ts.FunctionLikeDeclaration | null; file: ParsedFile | null; name: string } {
  const bare = unwrap(argument);
  if (isCallableBody(bare)) return { fn: bare, file, name: "" };
  if (ts.isIdentifier(bare)) {
    const target = resolveIdentifier(graph, file, bare);
    return { fn: target?.fn ?? null, file: target?.file ?? null, name: bare.text };
  }
  if (ts.isPropertyAccessExpression(bare)) {
    const name = expressionName(bare);
    const receiver = unwrap(bare.expression);
    if (ts.isIdentifier(receiver)) {
      const definition = graph.resolveMember(file, receiver.text, bare.name.text) ?? memberOfLocal(graph, file, receiver, bare.name.text);
      if (definition && isCallableBody(definition.node)) return { fn: definition.node, file: definition.file, name };
    }
    return { fn: null, file: null, name };
  }
  if (ts.isCallExpression(bare)) {
    const name = expressionName(bare.expression);
    // `asyncHandler(async (req, res) => …)`: the innermost function literal is the handler.
    for (const inner of bare.arguments) {
      const innerBare = unwrap(inner);
      if (isCallableBody(innerBare)) return { fn: innerBare, file, name };
    }
    // `wrap(handler)` where `handler` is a named function.
    const firstIdentifier = bare.arguments.map(unwrap).find(ts.isIdentifier);
    if (firstIdentifier && bare.arguments.length === 1) {
      const target = resolveIdentifier(graph, file, firstIdentifier);
      if (target) return { fn: target.fn, file: target.file, name };
    }
    return { fn: null, file: null, name };
  }
  return { fn: null, file: null, name: "" };
}

function memberOfLocal(graph: ModuleGraph, file: ParsedFile, receiver: ts.Identifier, member: string): Definition | null {
  const local = graph.localDefinition(file, receiver.text);
  return local ? graph.memberOf(local, member) : null;
}

function resolveIdentifier(graph: ModuleGraph, file: ParsedFile, identifier: ts.Identifier): { fn: ts.FunctionLikeDeclaration; file: ParsedFile } | null {
  // A synthetic call resolves the name exactly as a call written here would.
  const definition = graph.resolveLocal(file, identifier.text);
  if (definition && isCallableBody(definition.node)) return { fn: definition.node, file: definition.file };
  return null;
}

function middlewareRef(graph: ModuleGraph, file: ParsedFile, expression: ts.Expression): MiddlewareRef {
  const resolved = functionArgument(graph, file, expression);
  const name = resolved.name;
  const bare = unwrap(expression);
  // `passport.authenticate("jwt")`, `requireRole("admin")`: the call names the gate.
  const calledName = ts.isCallExpression(bare) ? expressionName(bare.expression) : name;
  const authenticates =
    AUTHENTICATES.test(calledName) || AUTHENTICATES.test(name) || (resolved.fn !== null && bodyAuthenticates(resolved.fn));
  const authorizes = AUTHORIZES.test(calledName) || AUTHORIZES.test(name) || (resolved.fn !== null && bodyAuthorizes(resolved.fn));
  return { expression, name: calledName || name, fn: resolved.fn, file: resolved.file, authenticates, authorizes };
}

/** The request parameter's position: Express error middleware takes the error first. */
function requestIndexOf(fn: ts.FunctionLikeDeclaration): number {
  const first = fn.parameters[0];
  if (fn.parameters.length === 4 && first && ts.isIdentifier(first.name) && /^(err|error|e)$/i.test(first.name.text)) return 1;
  return 0;
}

const handlerCache = new WeakMap<ts.SourceFile, RequestHandler[]>();

/** Every request handler registered in this file, wherever the handler function lives. */
export function requestHandlers(graph: ModuleGraph, file: ParsedFile): RequestHandler[] {
  const cached = handlerCache.get(file.source);
  if (cached) return cached;
  const found: RequestHandler[] = [];
  try {
    collect(graph, file, found);
  } catch {
    // A registration this cannot read contributes nothing, as before it existed.
  }
  handlerCache.set(file.source, found);
  return found;
}

function collect(graph: ModuleGraph, file: ParsedFile, found: RequestHandler[]): void {
  /** Router-level middleware seen so far, per receiver, in source order. */
  const routerMiddleware = new Map<string, MiddlewareRef[]>();

  const register = (
    receiverName: string,
    method: string,
    path: string | null,
    argumentsInOrder: readonly ts.Expression[],
    at: ts.Node,
    framework: string
  ): void => {
    if (argumentsInOrder.length === 0) return;
    const handlerArgument = argumentsInOrder[argumentsInOrder.length - 1]!;
    const handler = functionArgument(graph, file, handlerArgument);
    const middleware = [
      ...(routerMiddleware.get(receiverName) ?? []),
      ...argumentsInOrder.slice(0, -1).map((argument) => middlewareRef(graph, file, argument))
    ];
    // Middleware functions are request handlers too: they are called with the request.
    for (const ref of middleware) {
      if (!ref.fn || !ref.file || found.some((existing) => existing.fn === ref.fn)) continue;
      found.push({
        file: ref.file,
        registeredIn: file,
        fn: ref.fn,
        framework,
        method: "ANY",
        path,
        line: lineOf(file, at),
        requestParameters: [requestIndexOf(ref.fn)],
        middleware: [],
        isMiddleware: true
      });
    }
    if (!handler.fn || !handler.file) return;
    found.push({
      file: handler.file,
      registeredIn: file,
      fn: handler.fn,
      framework,
      method,
      path,
      line: lineOf(file, at),
      requestParameters: [requestIndexOf(handler.fn)],
      middleware,
      isMiddleware: false
    });
  };

  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node)) inspectCall(node);
    node.forEachChild(visit);
  };

  const inspectCall = (call: ts.CallExpression): void => {
    const callee = unwrap(call.expression);
    const tail = calleeTail(call);

    // `http.createServer(handler)`
    if (tail === "createServer" && call.arguments.length > 0) {
      const name = expressionName(call.expression);
      if (/^(http|https|http2|node:http|createServer)$|(^|\.)(http|https|http2)\.createServer$/.test(name) || name === "createServer") {
        const argument = call.arguments.find((candidate) => isCallableBody(unwrap(candidate)) || ts.isIdentifier(unwrap(candidate)));
        if (argument) register(`createServer@${call.pos}`, "ANY", null, [argument], call, "node-http");
      }
      return;
    }

    if (!ts.isPropertyAccessExpression(callee)) return;
    const receiver = unwrap(callee.expression);

    // `x.route("/path").get(handler)`
    if (VERBS.has(tail) && ts.isCallExpression(receiver) && calleeTail(receiver) === "route") {
      const path = stringLiteral(receiver.arguments[0]);
      if (path !== null && path.startsWith("/")) {
        register(expressionName(receiver.expression), tail === "all" ? "ANY" : tail.toUpperCase(), path, call.arguments, call, "express");
      }
      return;
    }

    if (!ts.isIdentifier(receiver) && !ts.isPropertyAccessExpression(receiver)) return;
    const receiverName = expressionName(receiver);
    const receiverTail = receiverName.split(".").pop() ?? receiverName;
    if (NOT_A_ROUTER.test(receiverTail)) return;

    // `x.use(fn)` / `x.use("/prefix", fn)` — router-level middleware.
    if (tail === "use") {
      const path = stringLiteral(call.arguments[0]);
      const functions = call.arguments.slice(path === null ? 0 : 1);
      const refs = functions.map((argument) => middlewareRef(graph, file, argument)).filter((ref) => ref.fn !== null || ref.name !== "");
      if (path === null) {
        const existing = routerMiddleware.get(receiverName) ?? [];
        routerMiddleware.set(receiverName, [...existing, ...refs]);
      }
      for (const ref of refs) {
        if (!ref.fn || !ref.file || found.some((existing) => existing.fn === ref.fn)) continue;
        // Only a function with a request-shaped arity: `use(router)` passes a router object.
        if (ref.fn.parameters.length < 1) continue;
        found.push({
          file: ref.file,
          registeredIn: file,
          fn: ref.fn,
          framework: "express",
          method: "ANY",
          path,
          line: lineOf(file, call),
          requestParameters: [requestIndexOf(ref.fn)],
          middleware: [],
          isMiddleware: true
        });
      }
      return;
    }

    // `x.get("/path", …middleware, handler)`
    if (VERBS.has(tail)) {
      const path = stringLiteral(call.arguments[0]);
      if (path === null || !path.startsWith("/")) return;
      const rest = call.arguments.slice(1);
      // Fastify's `x.get("/path", { preHandler }, handler)`.
      const options = rest.find((argument) => ts.isObjectLiteralExpression(unwrap(argument)));
      const callable = rest.filter((argument) => !ts.isObjectLiteralExpression(unwrap(argument)));
      const gates = options ? optionGates(unwrap(options) as ts.ObjectLiteralExpression) : [];
      if (callable.length === 0 && options) {
        const handler = propertyValue(unwrap(options) as ts.ObjectLiteralExpression, "handler");
        if (handler) register(receiverName, tail === "all" ? "ANY" : tail.toUpperCase(), path, [...gates, handler], call, "fastify");
        return;
      }
      register(receiverName, tail === "all" ? "ANY" : tail.toUpperCase(), path, [...gates, ...callable], call, options ? "fastify" : "express");
      return;
    }

    // Fastify `x.route({ method, url, handler, preHandler })`.
    if (tail === "route" && call.arguments.length === 1 && ts.isObjectLiteralExpression(unwrap(call.arguments[0]!))) {
      const object = unwrap(call.arguments[0]!) as ts.ObjectLiteralExpression;
      const url = stringLiteral(propertyValue(object, "url") ?? propertyValue(object, "path"));
      const methodValue = propertyValue(object, "method");
      const method = stringLiteral(methodValue)?.toUpperCase() ?? "ANY";
      const handler = propertyValue(object, "handler");
      if (handler && url) register(receiverName, method, url, [...optionGates(object), handler], call, "fastify");
    }
  };

  visit(file.source);

  // Next.js App Router: `app/**/route.ts` exporting HTTP verbs.
  if (/(^|\/)route\.[cm]?[jt]sx?$/.test(file.relativePath)) {
    for (const [name, fn] of exportedFunctions(graph, file)) {
      if (!NEXT_VERBS.has(name) || found.some((existing) => existing.fn === fn)) continue;
      found.push({
        file,
        registeredIn: file,
        fn,
        framework: "next-app-router",
        method: name,
        path: null,
        line: lineOf(file, fn),
        // The request, and the context object carrying the route params.
        requestParameters: fn.parameters.length > 1 ? [0, 1] : [0],
        middleware: [],
        isMiddleware: false
      });
    }
  }

  // Next.js pages API: the default export under `pages/api`.
  if (/(^|\/)pages\/api\//.test(file.relativePath)) {
    const definition = graph.exportOf(file, "default");
    const fn = definition && isCallableBody(definition.node) ? definition.node : null;
    if (fn && definition && !found.some((existing) => existing.fn === fn)) {
      found.push({
        file: definition.file,
        registeredIn: file,
        fn,
        framework: "next-pages-api",
        method: "ANY",
        path: null,
        line: lineOf(definition.file, fn),
        requestParameters: [0],
        middleware: [],
        isMiddleware: false
      });
    }
  }
}

function propertyValue(object: ts.ObjectLiteralExpression, key: string): ts.Expression | undefined {
  for (const property of object.properties) {
    if (ts.isPropertyAssignment(property) && property.name.getText().replace(/["']/g, "") === key) return property.initializer;
    if (ts.isShorthandPropertyAssignment(property) && property.name.text === key) return property.name;
    if (ts.isMethodDeclaration(property) && property.name.getText().replace(/["']/g, "") === key) {
      return property as unknown as ts.Expression;
    }
  }
  return undefined;
}

/** `preHandler`, `onRequest`, `preValidation`, `beforeHandler`: gates written as options. */
function optionGates(object: ts.ObjectLiteralExpression): ts.Expression[] {
  const gates: ts.Expression[] = [];
  for (const key of ["onRequest", "preValidation", "preHandler", "beforeHandler"]) {
    const value = propertyValue(object, key);
    if (!value) continue;
    const bare = unwrap(value);
    if (ts.isArrayLiteralExpression(bare)) gates.push(...bare.elements.filter((element): element is ts.Expression => !ts.isSpreadElement(element)));
    else gates.push(value);
  }
  return gates;
}

/** Exported functions of a module, including wrapped exports: `export const POST = withAuth(async (req) => …)`. */
function exportedFunctions(graph: ModuleGraph, file: ParsedFile): Map<string, ts.FunctionLikeDeclaration> {
  const out = new Map<string, ts.FunctionLikeDeclaration>();
  for (const statement of file.source.statements) {
    if (ts.isFunctionDeclaration(statement) && statement.name && statement.body) {
      const exported = ts.getModifiers(statement)?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword);
      if (exported) out.set(statement.name.text, statement);
      continue;
    }
    if (!ts.isVariableStatement(statement)) continue;
    const exported = ts.getModifiers(statement)?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword);
    if (!exported) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (!ts.isIdentifier(declaration.name) || !declaration.initializer) continue;
      const resolved = functionArgument(graph, file, declaration.initializer);
      if (resolved.fn && resolved.file === file) out.set(declaration.name.text, resolved.fn);
    }
  }
  return out;
}

/**
 * Is this function called with caller data as an argument, by contract?
 *
 * True for a registered handler or middleware, for any entry point an adapter in
 * `ast/frameworks/` recognised, and for a function with a parameter typed as a request.
 */
export function handlerPositions(graph: ModuleGraph, files: readonly ParsedFile[]): Map<ts.Node, RequestHandler> {
  const positions = new Map<ts.Node, RequestHandler>();
  for (const file of files) {
    for (const handler of requestHandlers(graph, file)) {
      if (!positions.has(handler.fn)) positions.set(handler.fn, handler);
    }
  }
  return positions;
}

/** Parameter types that are, by definition, an inbound request. */
const REQUEST_TYPES = /^(Request|NextRequest|IncomingMessage|FastifyRequest|HttpRequest|Express\.Request|express\.Request|APIGatewayProxyEvent\w*|APIGatewayProxyEventV2\w*|H3Event|RequestEvent)$/;

export function hasRequestTypedParameter(fn: ts.Node): boolean {
  const parameters = (fn as ts.FunctionLikeDeclaration).parameters ?? [];
  return parameters.some((parameter) => {
    if (!parameter.type || !ts.isTypeReferenceNode(parameter.type)) return false;
    return REQUEST_TYPES.test(parameter.type.typeName.getText());
  });
}

/**
 * Does this function take the request by the strongest naming conventions there are?
 *
 * `req` and `request` as a plain parameter, or a destructuring of the properties a
 * framework hands a handler — `{ params }`, `{ input }`, `{ query, body }`. Weaker names
 * the in-function model also accepts (`context`, `event`, `input`, `args`, `payload`) are
 * not enough to *start* a chain across functions: a CLI adapter's `context` is not a
 * request, and following it through three modules is how this repository's own source
 * was once reported.
 */
const CONVENTIONAL_REQUEST = /^(req|request)$/;
const FRAMEWORK_PROPERTIES = new Set(["params", "input", "query", "body", "searchParams", "headers", "cookies"]);

export function receivesRequestByConvention(fn: ts.Node): boolean {
  const parameters = (fn as ts.FunctionLikeDeclaration).parameters ?? [];
  return parameters.some((parameter) => {
    if (ts.isIdentifier(parameter.name)) return CONVENTIONAL_REQUEST.test(parameter.name.text);
    if (!ts.isObjectBindingPattern(parameter.name)) return false;
    return parameter.name.elements.some((element) => {
      const key = element.propertyName && ts.isIdentifier(element.propertyName)
        ? element.propertyName.text
        : ts.isIdentifier(element.name)
          ? element.name.text
          : null;
      return key !== null && FRAMEWORK_PROPERTIES.has(key);
    });
  });
}

/** What the middleware in front of a handler establishes, for a rule judging the handler. */
export interface RegistrationGate {
  /** Some middleware establishes who the caller is. */
  authenticates: boolean;
  /** Some middleware makes an authorisation decision. */
  authorizes: boolean;
  /** Every middleware's name as written in the registration, inline functions omitted. */
  names: string[];
}

/**
 * The middleware registered in front of any function in `chain` — a handler and the
 * functions enclosing it — wherever the registration is written. Null when none of them is
 * a registered handler, so a rule can tell "no gate" from "not known".
 */
export function registrationGate(file: ParsedFile, chain: readonly ts.Node[]): RegistrationGate | null {
  const handlerOf = file.requestHandlerOf;
  if (!handlerOf) return null;
  let gate: RegistrationGate | null = null;
  for (const fn of chain) {
    const handler = handlerOf(fn);
    if (!handler || handler.isMiddleware) continue;
    gate ??= { authenticates: false, authorizes: false, names: [] };
    for (const middleware of handler.middleware) {
      if (middleware.authenticates) gate.authenticates = true;
      if (middleware.authorizes) gate.authorizes = true;
      if (middleware.name) gate.names.push(middleware.name);
    }
  }
  return gate;
}

/** Is this function a request handler by any of the engine's means? */
export function isRequestHandler(file: ParsedFile, fn: ts.Node, handlers: ReadonlyMap<ts.Node, RequestHandler>): boolean {
  if (handlers.has(fn)) return true;
  // A parameter a framework's request decorator binds (`engine/decorators.ts`).
  if (file.requestSeeds?.has(fn)) return true;
  if (entryPointForFunction(file, fn)) return true;
  return hasRequestTypedParameter(fn) || receivesRequestByConvention(fn);
}

