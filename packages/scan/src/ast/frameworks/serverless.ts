import ts from "typescript";
import { collect, expressionName, literalTextOf } from "../helpers.js";
import { lineOf, type ParsedFile } from "../parse.js";
import {
  functionOf,
  importsFrom,
  joinRoute,
  parameterNames,
  stringArgument,
  type EntryPoint,
  type FrameworkAdapter,
  type TaintSeed
} from "../entrypoints.js";

/**
 * Serverless and edge handlers: AWS Lambda behind API Gateway, Cloudflare
 * Workers, Vercel and Netlify edge functions, Azure Functions, Google Cloud
 * Functions.
 *
 * These are the entry points with no registration call to find. There is no
 * `app.post("/refunds", ...)` anywhere in the repository — the wiring lives in a
 * `serverless.yml`, a `wrangler.toml` or a console setting, and the source only
 * exports a function under a conventional name. Discovery keyed to route
 * registration therefore sees nothing at all in these files, and nothing is
 * total: no entry point means no request parameter, no request parameter means no
 * taint, and every data-flow rule in the engine stays silent over a handler that
 * reads `event.pathParameters.id` straight into a query.
 *
 * The address is the honest half of the problem. A Lambda's URL is not in its own
 * source, so this adapter reports `ANY /` unless the body itself compares
 * `event.httpMethod` or `event.rawPath` against a literal. Admitting the path is
 * unknown is better than inventing one the reader would then fail to find.
 */

const HTTP_METHOD_LITERAL = /^(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)$/;

/** Names a serverless platform looks for when it loads a module. */
const HANDLER_NAME = /^(handler|main|lambdaHandler)$|Handler$/;

const AWS_MODULES = /(^|\/)aws-lambda$|^@aws-sdk\/|^aws-sdk$|^@aws-lambda-powertools\//;
const AZURE_MODULES = /^@azure\/functions$/;
const GCP_MODULES = /^@google-cloud\/functions-framework$/;
const EDGE_MODULES = /^cloudflare:|^@cloudflare\/|^@netlify\/edge-functions$|^@vercel\/edge$/;

/* ------------------------------------------------------------------ *
 * Origins
 *
 * The origin is quoted verbatim in evidence, so it has to read as the thing the
 * reader would look for in the handler. A destructured parameter needs a second
 * phrasing, because there the binding is one property of the payload rather than
 * the payload itself.
 * ------------------------------------------------------------------ */

interface Origin {
  whole: string;
  part: (property: string) => string;
}

const origin = (whole: string, root: string, suffix: string): Origin => ({
  whole,
  part: (property) => `${root}.${property} (${suffix})`
});

const AWS_EVENT = origin("event (inbound API Gateway request)", "event", "inbound API Gateway request");
const EDGE_REQUEST = origin("request (inbound request)", "request", "inbound request");
const FETCH_EVENT = origin("event.request (inbound request)", "event", "inbound request");
const AZURE_REQUEST = origin("req (inbound HTTP request)", "req", "inbound HTTP request");
const GCP_REQUEST = origin("req (inbound request)", "req", "inbound request");

/* ------------------------------------------------------------------ *
 * Export plumbing
 *
 * A serverless handler is identified by the name it is exported under, and the
 * several ways of writing that name are not interchangeable in the AST. Handling
 * only `export const handler` would miss every CommonJS Lambda, which is most of
 * the ones that exist.
 * ------------------------------------------------------------------ */

type AddExport = (name: string, fn: ts.Node | undefined, declaration: ts.Node, isDefault?: boolean) => void;

interface ExportedFunction {
  /** The name the platform's configuration references, or `default`. */
  name: string;
  fn: ts.Node;
  /** The node a reader would point at, which is the export, not the body. */
  declaration: ts.Node;
  isDefault: boolean;
}

function hasModifier(node: ts.Node, kind: ts.SyntaxKind): boolean {
  return ts.canHaveModifiers(node) && (ts.getModifiers(node)?.some((modifier) => modifier.kind === kind) ?? false);
}

function literalOf(node: ts.Node | undefined): string | null {
  return node ? literalTextOf(node) : null;
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

function propertyKey(file: ParsedFile, property: ts.ObjectLiteralElementLike): string {
  if (!property.name) return "";
  if (ts.isIdentifier(property.name) || ts.isStringLiteralLike(property.name)) return property.name.text;
  return property.name.getText(file.source).replace(/["'`]/g, "");
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

/** The value of one member of an object literal, whatever form it was written in. */
function memberValue(file: ParsedFile, object: ts.ObjectLiteralExpression, key: string): ts.Expression | undefined {
  for (const property of object.properties) {
    if (propertyKey(file, property) !== key) continue;
    if (ts.isPropertyAssignment(property)) return property.initializer;
    if (ts.isShorthandPropertyAssignment(property)) return property.name;
  }
  return undefined;
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

/** Every function this module exports, under the name the platform will use. */
function exportedFunctions(file: ParsedFile): ExportedFunction[] {
  const found: ExportedFunction[] = [];
  const add: AddExport = (name, fn, declaration, isDefault = false) => {
    if (fn) found.push({ name, fn, declaration, isDefault });
  };

  for (const statement of file.source.statements) {
    if (ts.isFunctionDeclaration(statement) && hasModifier(statement, ts.SyntaxKind.ExportKeyword)) {
      if (statement.body) {
        add(statement.name?.text ?? "default", statement, statement, hasModifier(statement, ts.SyntaxKind.DefaultKeyword));
      }
      continue;
    }

    if (ts.isVariableStatement(statement) && hasModifier(statement, ts.SyntaxKind.ExportKeyword)) {
      for (const declaration of statement.declarationList.declarations) {
        if (!ts.isIdentifier(declaration.name)) continue;
        add(declaration.name.text, functionOf(declaration.initializer), declaration);
      }
      continue;
    }

    // `export default <fn>` and TypeScript's `export = <fn>`. The second is how a
    // CommonJS Azure function is written once the project has been typed.
    if (ts.isExportAssignment(statement)) {
      const name = ts.isIdentifier(statement.expression) ? statement.expression.text : "default";
      add(name, functionValue(file, statement.expression), statement, !statement.isExportEquals);
      continue;
    }

    // `const handler = ...; export { handler };` is the same export written apart
    // from the definition, and a great deal of Lambda code is written that way.
    if (
      ts.isExportDeclaration(statement) &&
      statement.exportClause &&
      ts.isNamedExports(statement.exportClause) &&
      !statement.moduleSpecifier
    ) {
      for (const element of statement.exportClause.elements) {
        add(element.name.text, localFunction(file, (element.propertyName ?? element.name).text), element);
      }
      continue;
    }

    if (ts.isExpressionStatement(statement)) commonJsExports(file, statement, add);
  }

  return found;
}

/** `exports.handler = fn`, `module.exports = fn`, and `module.exports = { handler }`. */
function commonJsExports(file: ParsedFile, statement: ts.ExpressionStatement, add: AddExport): void {
  const assignment = statement.expression;
  if (!ts.isBinaryExpression(assignment) || assignment.operatorToken.kind !== ts.SyntaxKind.EqualsToken) return;

  const target = expressionName(assignment.left);
  const named = /^(?:module\.)?exports\.(.+)$/.exec(target);
  if (named) {
    add(named[1]!, functionValue(file, assignment.right), statement);
    return;
  }
  if (target !== "module.exports" && target !== "exports") return;

  const whole = functionValue(file, assignment.right);
  if (whole) {
    add("default", whole, statement, true);
    return;
  }
  // `module.exports = { handler }` exports the same function under a name the
  // platform can address, so the members matter individually.
  const object = unwrapObject(assignment.right);
  if (!object) return;
  for (const property of object.properties) {
    const key = propertyKey(file, property);
    if (key) add(key, memberFunction(file, object, key), property);
  }
}

/* ----------------- Reading an address out of a handler body ----------------- */

function isEquality(kind: ts.SyntaxKind): boolean {
  return (
    kind === ts.SyntaxKind.EqualsEqualsEqualsToken ||
    kind === ts.SyntaxKind.EqualsEqualsToken ||
    kind === ts.SyntaxKind.ExclamationEqualsEqualsToken ||
    kind === ts.SyntaxKind.ExclamationEqualsToken
  );
}

interface Address {
  method: string;
  path: string;
}

const UNKNOWN_ADDRESS: Address = { method: "ANY", path: "/" };

/**
 * The verb and route a handler dispatches on, read from its own comparisons.
 *
 * `classify` says what an accessed expression means — a verb, a route, or
 * neither. The first literal of each kind wins: a handler that branches over
 * several routes has no single address, and the first branch is at least a real
 * one rather than a merger of two.
 */
function addressFrom(fn: ts.Node, classify: (accessed: ts.Node) => "method" | "path" | null): Address {
  let method: string | null = null;
  let path: string | null = null;

  for (const comparison of collect(fn, ts.isBinaryExpression)) {
    if (!isEquality(comparison.operatorToken.kind)) continue;
    for (const [accessed, other] of [
      [comparison.left, comparison.right],
      [comparison.right, comparison.left]
    ] as const) {
      const literal = literalTextOf(other);
      if (literal === null) continue;
      const kind = classify(accessed);
      if (kind === "method" && method === null && HTTP_METHOD_LITERAL.test(literal.toUpperCase())) {
        method = literal.toUpperCase();
      }
      if (kind === "path" && path === null && literal.startsWith("/")) path = literal;
    }
  }

  return { method: method ?? UNKNOWN_ADDRESS.method, path: path ?? UNKNOWN_ADDRESS.path };
}

/* ---------------------------------- Seeds ---------------------------------- */

/**
 * The caller-controlled bindings a handler's request parameter introduces.
 *
 * Seeding the parameter root is enough. The taint model already walks property
 * accesses off a tainted root, so naming `event` covers
 * `event.queryStringParameters`, `event.pathParameters` and
 * `event.requestContext.authorizer` without this adapter enumerating a payload
 * format AWS keeps revising. What the model cannot do on its own is recognise
 * the root when it is called `apiEvent`, and that is what the seed supplies.
 *
 * A destructured parameter has no root to name, so each bound property is seeded
 * individually — those bindings hold event data with the same certainty the root
 * does, and dropping them would lose the whole flow in a handler written
 * `async ({ pathParameters, body }) => {}`.
 */
function requestSeeds(fn: ts.Node, index: number, origin: Origin): TaintSeed[] {
  const parameter = (fn as ts.FunctionLikeDeclaration).parameters?.[index];
  if (!parameter) return [];
  if (ts.isIdentifier(parameter.name)) return [{ name: parameter.name.text, origin: origin.whole }];
  if (!ts.isObjectBindingPattern(parameter.name)) return [];

  const seeds: TaintSeed[] = [];
  for (const element of parameter.name.elements) {
    if (!ts.isIdentifier(element.name)) continue;
    const property =
      element.propertyName && ts.isIdentifier(element.propertyName) ? element.propertyName.text : element.name.text;
    seeds.push({ name: element.name.text, origin: origin.part(property) });
  }
  return seeds;
}

/** Parameter names at the given positions, for the runtime's own arguments. */
function trustedAt(fn: ts.Node, ...indices: number[]): string[] {
  const names = parameterNames(fn);
  return indices.map((index) => names[index]).filter((name): name is string => Boolean(name));
}

/** Assemble the optional halves of an entry point without empty arrays in the report. */
function withHandler(fn: ts.Node, seeds: TaintSeed[], trusted: string[]): Partial<EntryPoint> {
  return {
    node: fn,
    ...(seeds.length > 0 ? { seeds } : {}),
    ...(trusted.length > 0 ? { trustedParameters: trusted } : {})
  };
}

/* ------------------------ AWS Lambda and API Gateway ------------------------ */

/**
 * Properties that only exist on an API Gateway or event-source payload.
 *
 * This is the discriminator for the whole Lambda shape. `export const handler`
 * appears in queue workers, test doubles, CLI wrappers and framework glue all
 * over npm; a handler that reaches into one of these properties is answering an
 * AWS event and nothing else.
 */
const AWS_EVENT_PROPERTIES = new Set([
  "httpMethod", "path", "rawPath", "resource", "headers", "multiValueHeaders", "body", "queryStringParameters",
  "multiValueQueryStringParameters", "rawQueryString", "pathParameters", "requestContext", "stageVariables",
  "isBase64Encoded", "cookies"
]);

/** Paths on the event that hold the verb, across both payload format versions. */
const AWS_METHOD_ACCESSORS = new Set(["httpMethod", "requestContext.httpMethod", "requestContext.http.method"]);

/** Paths on the event that hold the route. */
const AWS_PATH_ACCESSORS = new Set([
  "path", "rawPath", "resource", "requestContext.path", "requestContext.resourcePath", "requestContext.http.path"
]);

/** Every property of the first parameter this function reads, however it reads it. */
function firstParameterProperties(fn: ts.Node): Set<string> {
  const properties = new Set<string>();
  const parameter = (fn as ts.FunctionLikeDeclaration).parameters?.[0];
  if (!parameter) return properties;

  if (ts.isObjectBindingPattern(parameter.name)) {
    for (const element of parameter.name.elements) {
      const property = element.propertyName ?? element.name;
      if (ts.isIdentifier(property)) properties.add(property.text);
    }
    return properties;
  }
  if (!ts.isIdentifier(parameter.name)) return properties;

  const root = parameter.name.text;
  for (const access of collect(fn, ts.isPropertyAccessExpression)) {
    if (ts.isIdentifier(access.expression) && access.expression.text === root) properties.add(access.name.text);
  }
  for (const access of collect(fn, ts.isElementAccessExpression)) {
    if (!ts.isIdentifier(access.expression) || access.expression.text !== root) continue;
    const key = literalTextOf(access.argumentExpression);
    if (key) properties.add(key);
  }
  return properties;
}

function lambdaEntryPoints(file: ParsedFile, claimed: Set<ts.Node>): EntryPoint[] {
  const importsAws = importsFrom(file, AWS_MODULES);
  const entries: EntryPoint[] = [];

  for (const exported of exportedFunctions(file)) {
    if (claimed.has(exported.fn) || !HANDLER_NAME.test(exported.name)) continue;

    const properties = firstParameterProperties(exported.fn);
    const readsAwsEvent = [...properties].some((property) => AWS_EVENT_PROPERTIES.has(property));
    // The two gates. Without the second one, every `export const handler` in the
    // ecosystem — Express glue, a test double, a React callback — would be
    // announced as an API Gateway route.
    if (!importsAws && !readsAwsEvent) continue;

    // A handler taking no arguments answers a schedule, not a caller. It has no
    // request to seed, and claiming a route for it would be pure noise.
    const parameters = (exported.fn as ts.FunctionLikeDeclaration).parameters;
    if (!parameters || parameters.length === 0) continue;

    claimed.add(exported.fn);
    const root = parameterNames(exported.fn)[0] ?? null;

    // An event-source handler is fed by SQS, SNS, S3 or a stream: it has no verb
    // and no path, and the queue adapter already declares it with the name of the
    // source that fills it. Two adapters describing one handler would put the same
    // function in the report twice, so this one steps aside.
    if (properties.has("Records") && !properties.has("httpMethod") && !properties.has("rawPath")) continue;

    const address =
      root === null
        ? UNKNOWN_ADDRESS
        : addressFrom(exported.fn, (accessed) => {
            const name = expressionName(accessed as ts.Expression);
            if (!name.startsWith(`${root}.`)) return null;
            const accessor = name.slice(root.length + 1);
            if (AWS_METHOD_ACCESSORS.has(accessor)) return "method";
            if (AWS_PATH_ACCESSORS.has(accessor)) return "path";
            return null;
          });

    entries.push({
      framework: "serverless",
      kind: "http",
      method: address.method,
      path: address.path,
      line: lineOf(file, exported.declaration),
      // The second argument is the Lambda context: request id, remaining time,
      // the function's own identity. The generic model reads a parameter named
      // `context` as caller data, and every flow it derives from one is a lie.
      ...withHandler(exported.fn, requestSeeds(exported.fn, 0, AWS_EVENT), trustedAt(exported.fn, 1))
    });
  }

  return entries;
}

/* --------------- Cloudflare Workers, Vercel and Netlify edge --------------- */

/** Properties that mean a parameter is being used as a `Request`. */
const REQUEST_PROPERTIES = new Set([
  "url", "headers", "method", "body", "json", "text", "formData", "arrayBuffer", "blob", "cf", "signal"
]);

/**
 * The exported `config` object an edge platform reads.
 *
 * Netlify puts the route there — `export const config = { path: "/receipts" }` —
 * which is the one place in this family where the source really does state its
 * own address. Vercel puts `runtime: "edge"` there, which gives no path but does
 * settle that a bare default export is an edge function and not a page component.
 */
interface EdgeConfig {
  paths: string[];
  methods: string[];
  isEdge: boolean;
}

function literalList(value: ts.Expression | undefined): string[] {
  const single = literalOf(value);
  if (single !== null) return [single];
  if (value && ts.isArrayLiteralExpression(value)) {
    return value.elements.map((element) => literalTextOf(element)).filter((text): text is string => text !== null);
  }
  return [];
}

function edgeConfig(file: ParsedFile): EdgeConfig {
  const config: EdgeConfig = { paths: [], methods: [], isEdge: false };

  for (const statement of file.source.statements) {
    if (!ts.isVariableStatement(statement) || !hasModifier(statement, ts.SyntaxKind.ExportKeyword)) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (!ts.isIdentifier(declaration.name) || !declaration.initializer) continue;
      if (declaration.name.text === "runtime") {
        if (literalOf(declaration.initializer) === "edge") config.isEdge = true;
        continue;
      }
      if (declaration.name.text !== "config") continue;
      const object = unwrapObject(declaration.initializer);
      if (!object) continue;
      if (literalOf(memberValue(file, object, "runtime")) === "edge") config.isEdge = true;
      config.paths.push(...literalList(memberValue(file, object, "path")).filter((value) => value.startsWith("/")));
      config.methods.push(
        ...[...literalList(memberValue(file, object, "method")), ...literalList(memberValue(file, object, "methods"))]
          .map((method) => method.toUpperCase())
          .filter((method) => HTTP_METHOD_LITERAL.test(method))
      );
      if (config.paths.length > 0 || config.methods.length > 0) config.isEdge = true;
    }
  }

  return config;
}

function requestAddress(fn: ts.Node): Address {
  const root = parameterNames(fn)[0] ?? null;
  return addressFrom(fn, (accessed) => {
    const name = expressionName(accessed as ts.Expression);
    // The pathname is nearly always read off a `new URL(request.url)` local, so
    // it is recognised by its own tail rather than through the parameter.
    if (name === "pathname" || name.endsWith(".pathname")) return "path";
    if (root !== null && name === `${root}.method`) return "method";
    return null;
  });
}

function workerEntryPoints(file: ParsedFile, claimed: Set<ts.Node>): EntryPoint[] {
  const entries: EntryPoint[] = [];
  const config = edgeConfig(file);
  const importsEdge = importsFrom(file, EDGE_MODULES);
  // A Next.js `pages/api` default export is that framework's own shape and its
  // own adapter's business. Claiming it here would report the same handler twice,
  // under an address this adapter resolves worse than the file path does.
  const isNextPagesApi = /(^|\/)pages\/api\//.test(file.relativePath);

  const record = (fn: ts.Node, declaration: ts.Node, origin: Origin, trusted: number[]): void => {
    if (claimed.has(fn)) return;
    claimed.add(fn);
    const derived = requestAddress(fn);
    // A declared config wins over a comparison in the body: it is the platform's
    // own statement of the address, while the comparison is only one branch.
    const paths = config.paths.length > 0 ? config.paths : [derived.path];
    const methods = config.methods.length > 0 ? config.methods : [derived.method];
    for (const path of paths) {
      for (const method of methods) {
        entries.push({
          framework: "serverless",
          kind: "http",
          method,
          path,
          line: lineOf(file, declaration),
          // `env` holds the Worker's bindings — secrets, KV namespaces, queues —
          // and `ctx` is the runtime's execution handle. Neither is anything the
          // caller chose, and `context` in particular is a name the generic model
          // reads as attacker data.
          ...withHandler(fn, requestSeeds(fn, 0, origin), trustedAt(fn, ...trusted))
        });
      }
    }
  };

  for (const exported of exportedFunctions(file)) {
    if (!exported.isDefault || isNextPagesApi) continue;
    const parameters = (exported.fn as ts.FunctionLikeDeclaration).parameters;
    if (!parameters || parameters.length === 0) continue;

    // Either the file says it is an edge function, or its default export takes a
    // single argument it uses as a Request. A two-argument `(req, res)` default
    // export with no edge marker is an Express or Next.js handler, and this
    // adapter has no business speaking for it.
    const looksEdge = config.isEdge || importsEdge || (parameters.length === 1 && readsRequest(exported.fn));
    if (!looksEdge) continue;
    record(exported.fn, exported.declaration, EDGE_REQUEST, [1, 2]);
  }

  // `export default { async fetch(request, env, ctx) {} }` — the module Worker
  // shape, and also what Bun and Deno accept.
  for (const statement of file.source.statements) {
    if (!ts.isExportAssignment(statement) || statement.isExportEquals) continue;
    const object = unwrapObject(statement.expression);
    const fetchHandler = object ? memberFunction(file, object, "fetch") : undefined;
    if (!fetchHandler) continue;
    if (((fetchHandler as ts.FunctionLikeDeclaration).parameters?.length ?? 0) === 0) continue;
    record(fetchHandler, fetchHandler, EDGE_REQUEST, [1, 2]);
  }

  // `addEventListener("fetch", (event) => {})` — the service-worker shape Workers
  // started with. The parameter is a FetchEvent whose `request` is the caller's.
  for (const call of collect(file.source, ts.isCallExpression)) {
    const callee = expressionName(call.expression);
    if (!/^(?:self\.|globalThis\.)?addEventListener$/.test(callee)) continue;
    if (stringArgument(call, 0) !== "fetch") continue;
    const fn = functionValue(file, call.arguments[1]);
    if (!fn || claimed.has(fn)) continue;
    claimed.add(fn);
    entries.push({
      framework: "serverless",
      kind: "http",
      method: "ANY",
      path: "/",
      line: lineOf(file, call),
      ...withHandler(fn, requestSeeds(fn, 0, FETCH_EVENT), [])
    });
  }

  return entries;
}

function readsRequest(fn: ts.Node): boolean {
  return [...firstParameterProperties(fn)].some((property) => REQUEST_PROPERTIES.has(property));
}

/* ----------------------- itty-router inside a Worker ----------------------- */

const ROUTER_FACTORIES = /^(Router|AutoRouter|IttyRouter)$/;
const ROUTER_METHODS = new Set(["get", "post", "put", "patch", "delete", "options", "head", "all"]);

/**
 * Router variables created by itty's own factories, with their base path.
 *
 * The receiver has to have been produced by one of these calls. Generic route
 * discovery already reads `router.get("/x", handler)` for its address, but it
 * cannot know that the first parameter of an itty handler is the Request, and
 * that is the half that turns the route into an analysable entry point.
 */
function ittyRouters(file: ParsedFile): Map<string, string> {
  const routers = new Map<string, string>();
  for (const declaration of collect(file.source, ts.isVariableDeclaration)) {
    if (!ts.isIdentifier(declaration.name) || !declaration.initializer) continue;
    const call = declaration.initializer;
    if (!ts.isCallExpression(call) || !ts.isIdentifier(call.expression)) continue;
    if (!ROUTER_FACTORIES.test(call.expression.text)) continue;
    const options = unwrapObject(call.arguments[0]);
    routers.set(declaration.name.text, (options ? literalOf(memberValue(file, options, "base")) : null) ?? "");
  }
  return routers;
}

function ittyEntryPoints(file: ParsedFile, claimed: Set<ts.Node>): EntryPoint[] {
  const routers = ittyRouters(file);
  if (routers.size === 0) return [];

  const entries: EntryPoint[] = [];
  for (const call of collect(file.source, ts.isCallExpression)) {
    if (!ts.isPropertyAccessExpression(call.expression)) continue;
    const receiver = call.expression.expression;
    if (!ts.isIdentifier(receiver)) continue;
    const base = routers.get(receiver.text);
    if (base === undefined) continue;
    const method = call.expression.name.text.toLowerCase();
    if (!ROUTER_METHODS.has(method)) continue;
    const route = stringArgument(call, 0);
    if (route === null) continue;

    // itty passes the request down a chain, so the handler that matters is the
    // last argument. Anything before it is middleware over the same request.
    const handler = [...call.arguments]
      .reverse()
      .map((argument) => functionValue(file, argument))
      .find((fn): fn is ts.Node => Boolean(fn) && !claimed.has(fn as ts.Node));
    if (handler) claimed.add(handler);

    entries.push({
      framework: "serverless",
      kind: "http",
      method: method === "all" ? "ANY" : method.toUpperCase(),
      path: joinRoute(base, route),
      line: lineOf(file, call),
      ...(handler ? withHandler(handler, requestSeeds(handler, 0, EDGE_REQUEST), trustedAt(handler, 1, 2)) : {})
    });
  }
  return entries;
}

/* ----------------------------- Azure Functions ----------------------------- */

function azureEntryPoints(file: ParsedFile, claimed: Set<ts.Node>): EntryPoint[] {
  const entries: EntryPoint[] = [];

  // The v4 programming model: `app.http('name', { methods, route, handler })`.
  // `app` is as common a variable name as exists, so the import is what settles
  // that this particular `app.http` is Azure's registration and not a helper on
  // somebody's own object.
  const isAzure = importsFrom(file, AZURE_MODULES);
  for (const call of collect(file.source, ts.isCallExpression)) {
    if (!isAzure || expressionName(call.expression) !== "app.http") continue;
    const name = stringArgument(call, 0);
    const options = unwrapObject(call.arguments[1]);
    if (name === null || !options) continue;

    const handler = memberFunction(file, options, "handler");
    const route = literalOf(memberValue(file, options, "route"));
    const methods = literalList(memberValue(file, options, "methods"))
      .map((method) => method.toUpperCase())
      .filter((method) => HTTP_METHOD_LITERAL.test(method));

    // The deployed URL carries a prefix configured in `host.json`, which is not in
    // this file. The declared route is what the source itself states, so that is
    // what gets reported rather than a guessed `/api` in front of it.
    const path = joinRoute(route ?? name);
    const claimable = handler !== undefined && !claimed.has(handler);
    if (handler && claimable) claimed.add(handler);

    for (const method of methods.length > 0 ? methods : ["ANY"]) {
      entries.push({
        framework: "serverless",
        kind: "http",
        method,
        path,
        line: lineOf(file, call),
        // Azure's `InvocationContext` carries the logger, the invocation id and
        // the output bindings. It is named `context` by convention, so it is
        // precisely the parameter the generic model gets wrong.
        ...(handler && claimable
          ? withHandler(handler, requestSeeds(handler, 0, EDGE_REQUEST), trustedAt(handler, 1))
          : {})
      });
    }
  }

  // The v3 model: `module.exports = async function (context, req) {}`. The request
  // is the *second* parameter, inverting the assumption every other shape in this
  // file can make, and the first — `context` — belongs to the runtime.
  for (const exported of exportedFunctions(file)) {
    if (!exported.isDefault || claimed.has(exported.fn)) continue;
    const names = parameterNames(exported.fn);
    if (names[0] !== "context") continue;
    if (names[1] !== "req" && names[1] !== "request") continue;
    claimed.add(exported.fn);
    entries.push({
      framework: "serverless",
      kind: "http",
      method: "ANY",
      path: "/",
      line: lineOf(file, exported.declaration),
      ...withHandler(exported.fn, requestSeeds(exported.fn, 1, AZURE_REQUEST), trustedAt(exported.fn, 0))
    });
  }

  return entries;
}

/* -------------------------- Google Cloud Functions -------------------------- */

function gcpEntryPoints(file: ParsedFile, claimed: Set<ts.Node>): EntryPoint[] {
  if (!importsFrom(file, GCP_MODULES)) return [];
  const entries: EntryPoint[] = [];
  for (const call of collect(file.source, ts.isCallExpression)) {
    if (!ts.isPropertyAccessExpression(call.expression) || call.expression.name.text !== "http") continue;
    // `app.http` is Azure and is handled above; the functions framework is
    // conventionally imported under `functions` or `ff`.
    const receiver = expressionName(call.expression.expression);
    if (receiver !== "functions" && receiver !== "ff") continue;
    const name = stringArgument(call, 0);
    const handler = functionValue(file, call.arguments[1]);
    if (name === null || !handler || claimed.has(handler)) continue;
    claimed.add(handler);

    entries.push({
      framework: "serverless",
      kind: "http",
      method: "ANY",
      path: joinRoute(name),
      line: lineOf(file, call),
      // The functions framework hands over Express request and response objects,
      // so only the first parameter is the caller's.
      ...withHandler(handler, requestSeeds(handler, 0, GCP_REQUEST), [])
    });
  }
  return entries;
}

/* ------------------------------- The adapter ------------------------------- */

/**
 * The text pre-check.
 *
 * It has to be cheap, because it runs for every adapter over every file, and it
 * has to be strict, because a file that merely mentions `handler` is not a
 * Lambda. Each clause names a token that does not appear in code belonging to
 * some other framework; the AST gates in `detect` then re-check every one of them
 * properly.
 */
function applies(file: ParsedFile): boolean {
  const text = file.text;

  const exportsAHandler =
    /\b(?:module\.exports|exports\s*\.|export\s+(?:default\s+|\{)|export\s+(?:const|let|var|async|function))/.test(text) &&
    /\b(?:handler|main|lambdaHandler|[A-Za-z0-9_$]+Handler)\b/.test(text);
  const awsSignal =
    exportsAHandler &&
    (/["'](?:[^"']*\/)?aws-lambda["']|@aws-sdk\/|["']aws-sdk["']/.test(text) ||
      /\b(?:httpMethod|rawPath|rawQueryString|queryStringParameters|multiValueQueryStringParameters|pathParameters|requestContext|stageVariables|isBase64Encoded)\b/.test(
        text
      ) ||
      // `headers`, `body` and `path` are far too common to look for on their own,
      // but read off a root whose name ends in `event` they are the API Gateway
      // payload and nothing else.
      /\b\w*[eE]vent\.(?:headers|body|path|resource|cookies|multiValueHeaders)\b/.test(text));

  const workerSignal =
    /export\s+default\s*\{[\s\S]{0,240}?\bfetch\s*[(:]/.test(text) ||
    /addEventListener\s*\(\s*["']fetch["']/.test(text) ||
    /\bruntime\s*[:=]\s*["']edge["']/.test(text) ||
    (/export\s+default\s+(?:async\s+)?(?:function|\()/.test(text) &&
      // Netlify and Vercel both declare an edge function by exporting a `config`
      // beside the default export, and Netlify puts the route in it.
      (/@netlify\/edge-functions|@vercel\/edge|@cloudflare\/|cloudflare:/.test(text) ||
        /export\s+const\s+config\s*[:=]/.test(text)));

  const ittySignal = /\b(?:Router|AutoRouter|IttyRouter)\s*\(/.test(text);
  const azureSignal = /@azure\/functions/.test(text) || /\bapp\.http\s*\(/.test(text) || /\(\s*context\s*,\s*req\b/.test(text);
  const gcpSignal = /@google-cloud\/functions-framework/.test(text) || /\b(?:functions|ff)\.http\s*\(/.test(text);

  return awsSignal || workerSignal || ittySignal || azureSignal || gcpSignal;
}

function detect(file: ParsedFile): EntryPoint[] {
  // One function is one entry point. A Worker that also imports `@aws-sdk` would
  // otherwise be announced twice, once per family, and the second announcement
  // would carry the wrong trusted parameters. The order below runs the shapes
  // that name their own address before the ones that have to fall back to `ANY /`.
  const claimed = new Set<ts.Node>();
  return [
    ...azureEntryPoints(file, claimed),
    ...gcpEntryPoints(file, claimed),
    ...ittyEntryPoints(file, claimed),
    ...lambdaEntryPoints(file, claimed),
    ...workerEntryPoints(file, claimed)
  ];
}

export const serverlessAdapter: FrameworkAdapter = { id: "serverless", applies, detect };

/**
 * The registry names Lambda, edge and Azure separately, and they are one adapter
 * on purpose.
 *
 * These families overlap inside a single file: an `export default async function
 * handler(event)` in a module that imports `aws-lambda` matches the Lambda shape
 * and the edge shape both. Run as separate adapters they would each claim that
 * function and the report would carry two entry points for one handler, the
 * second one insisting the caller controls a parameter the first one calls the
 * runtime's. One `detect` pass with one claimed set is what makes each function
 * belong to exactly one shape. `registerAdapter` deduplicates by id, so
 * registering all three of these names registers the pass once.
 */
export const lambdaAdapter = serverlessAdapter;
export const edgeAdapter = serverlessAdapter;
export const azureAdapter = serverlessAdapter;
/** Google Cloud Functions ride along with the same pass; kept named for the registry. */
export const gcpAdapter = serverlessAdapter;
