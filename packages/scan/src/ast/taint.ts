import ts from "typescript";
import type { ParsedFile } from "./parse.js";
import { calleeName, calleeTail, dynamicParts, expressionName, isConstantString, walk, isAbortCall } from "./helpers.js";
import { entryPointForFunction } from "./entrypoints.js";
import {
  constrainedValue,
  defaultSchemaResolver,
  schemaCheck,
  schemaParse,
  schemaViewOf,
  stepView,
  type SchemaFacts,
  type SchemaShape,
  type SchemaView
} from "../engine/validation.js";

/**
 * Taint tracking within one function body.
 *
 * Inside the body, taint is followed through local bindings, template literals, string
 * concatenation, loops and element callbacks, object fields, and a short list of
 * pass-through calls. What crosses a function boundary arrives as seeds that `scan`
 * computed beforehand — `engine/interproc.ts`, `engine/handlers.ts`,
 * `engine/decorators.ts` — and calls into project functions are answered by summaries
 * (`engine/summaries.ts`); see `packages/scan/ENGINE.md` and ADR 018. Everything it cannot
 * follow is reported as a coverage limitation rather than guessed at, because a scanner
 * that quietly over-reaches produces exactly the false positives this engine exists to
 * avoid.
 */

/** Parameter names that conventionally carry the inbound request. */
const REQUEST_PARAMETER_NAMES = new Set([
  "req",
  "request",
  "ctx",
  "context",
  "event",
  "c",
  "input",
  "args",
  // A server action's whole input arrives as a FormData argument. Without these the
  // entire server-action surface is invisible to data-flow analysis.
  "formData",
  "form",
  "payload",
  "body"
]);

/** Parameter types that are, by definition, the caller's own data. */
const REQUEST_PARAMETER_TYPES = /^(FormData|URLSearchParams|Request|NextRequest|IncomingMessage)$/;

/**
 * Property paths on a request object that a caller controls.
 *
 * The list is deliberately cross-runtime. An API Gateway event spells the query
 * string `queryStringParameters` and a BullMQ job spells its payload `data`;
 * a model that only knows Express's four names sees none of it.
 */
const REQUEST_PROPERTIES = new Set([
  "query",
  "body",
  "params",
  "headers",
  "cookies",
  "url",
  "search",
  "form",
  // AWS API Gateway and Lambda function URLs.
  "queryStringParameters",
  "multiValueQueryStringParameters",
  "pathParameters",
  "rawQueryString",
  "rawPath",
  "path",
  "resource",
  // Queue and stream payloads.
  "data",
  "Records",
  "value",
  "content",
  "payload",
  "message",
  "attributes",
  // Web platform.
  "searchParams",
  "formData"
]);

/**
 * Properties middleware attaches to the request, which are server-derived and are
 * NOT caller-controlled.
 *
 * `request.user.accountId` is the authenticated subject, put there by the auth layer
 * after verifying a session. Treating it as attacker data makes every correctly
 * scoped query look like a defect, which is the fastest way to make a scanner
 * useless.
 */
const SERVER_ATTACHED_PROPERTIES = new Set([
  "user",
  "session",
  "auth",
  "viewer",
  "account",
  "actor",
  "subject",
  "state",
  "locals",
  "principal",
  "identity",
  "membership",
  "tenant",
  "workspace",
  "db",
  "log",
  "logger"
]);

/** Calls whose result is caller-controlled regardless of the receiver. */
const TAINTED_CALLS = new Set([
  "searchParams.get",
  "searchParams.getAll",
  "nextUrl.searchParams.get",
  "url.searchParams.get",
  "formData.get",
  "req.header",
  "request.header",
  "req.get",
  "headers.get"
]);

/** Calls that return caller-controlled data when awaited on a request. */
const TAINTED_BODY_READERS = new Set(["json", "text", "formData", "arrayBuffer", "blob"]);

/**
 * Accessors that read caller data off a framework's own context object.
 *
 * Hono hands the request through `c.req.param("id")`, Koa through `ctx.query`,
 * Fastify through `request.params`. A model that only understands `req.query` is
 * blind in three of the four frameworks people actually use.
 */
const CONTEXT_ACCESSORS = new Set([
  "param",
  "params",
  "query",
  "queries",
  "header",
  "headers",
  "cookie",
  "cookies",
  "parseBody",
  "valid",
  "searchParams"
]);

/**
 * Calls that pass their taint straight through. Anything not listed here breaks
 * the chain, which biases the engine toward missing a finding rather than
 * inventing one.
 */
const PASS_THROUGH_CALLS = new Set([
  "String",
  "decodeURI",
  "decodeURIComponent",
  "encodeURI",
  "encodeURIComponent",
  "trim",
  "toString",
  "toLowerCase",
  "toUpperCase",
  "concat",
  "slice",
  "substring",
  "substr",
  "replace",
  "replaceAll",
  "split",
  "join",
  "at",
  "normalize",
  "padStart",
  "padEnd",
  "JSON.parse"
]);

/**
 * Calls that make a value safe for *every* sink, by turning it into something
 * that is no longer attacker-controlled text.
 *
 * `String` is deliberately absent: `String(x)` on a string returns that string
 * unchanged, so it converts a type without constraining a value. It belongs in
 * the pass-through list, and it is there.
 */
const UNIVERSAL_SANITIZERS = new Set(["Number", "parseInt", "parseFloat", "BigInt", "Boolean"]);

/** The subset of those that keep the caller's *value* while removing its text. */
const NUMERIC_COERCIONS = new Set(["Number", "parseInt", "parseFloat", "BigInt"]);

/** Escapers that make a value safe for HTML output specifically. */
export const HTML_ESCAPERS = new Set([
  "sanitizeHtml",
  "sanitize",
  "sanitizeHTML",
  "DOMPurify.sanitize",
  "purify.sanitize",
  "xss",
  "clean",
  "escapeHTML",
  "escapeHtml",
  "escapeHTML",
  "htmlEscape",
  "escape",
  "sanitize",
  "sanitizeHtml",
  "DOMPurify.sanitize",
  "encodeHtml",
  "he.encode"
]);

export interface TaintedRoot {
  /** The local binding name that holds attacker-controlled data. */
  name: string;
  /** Human-readable origin, used verbatim in evidence. */
  origin: string;
  declaration: ts.Node;
}

export interface TaintScope {
  fn: ts.Node;
  roots: Map<string, TaintedRoot>;
  /** Bindings proven safe by a guard or a sanitizing call. */
  cleared: Set<string>;
  /** Bindings that passed an HTML-escaping call. */
  htmlSafe: Set<string>;
  /**
   * Functions declared in this file whose *body* HTML-escapes, whatever they are
   * called. Computed once per file rather than per interpolation slot.
   */
  htmlEscapers: Set<string>;
  /** Bindings constrained by an allowlist membership guard. */
  allowlisted: Set<string>;
  /** Bindings resolved and then checked for containment in a base directory. */
  containmentChecked: Set<string>;
  /**
   * Bindings cleared *only* because they were coerced to a number. Numeric
   * coercion removes the ability to inject text, so injection rules are right to
   * treat it as sanitizing — but the value is still whatever the caller chose,
   * which is exactly the bug in a price calculation.
   */
  coerced: Set<string>;
  /**
   * Dotted paths cleared by an equality comparison, such as `request.method`.
   * Comparing one property to a literal says nothing about the rest of the
   * object, so clearing the whole root there would lose most real flows.
   */
  clearedPaths: Set<string>;
  /**
   * Local arrays and string builders that have received attacker-controlled data.
   *
   * Building a query out of a `clauses` array and joining it is one of the most
   * common shapes real SQL injection takes, and it is invisible to a model that
   * only follows direct assignment. `clauses.push(`status = '${status}'`)` puts
   * taint into the array; `clauses.join(" AND ")` takes it out again.
   */
  taintedCollections: Map<string, string>;
  /**
   * What each local binding was initialised from, so a rule that needs the *shape*
   * of a value — is this string SQL, does it contain markup — can look at the
   * expression rather than at the variable's name.
   */
  initializers: Map<string, ts.Expression>;
  /**
   * Free functions that hand back caller data when called with this handler's
   * request object, declared by the entry point that owns the handler.
   *
   * h3 delivers every piece of caller input this way — `getQuery(event)`,
   * `readBody(event)`, `getRouterParam(event, "id")` — and a model that only
   * understands property access is blind to all of it. The set is per-scope
   * rather than global because `getQuery` means nothing in a file that does not
   * use h3, and a global list would taint an unrelated helper of the same name.
   */
  accessors: Set<string>;
  /**
   * Dotted paths that hold caller data although their root does not: `options.term`
   * when a caller passed `{ term: req.query.q, user: req.user }` as `options`.
   *
   * Seeded from `ParsedFile.propertySeeds`. Optional so a scope built by hand elsewhere
   * stays valid.
   */
  taintedPaths?: Map<string, string>;
  /** The file this scope belongs to, so the model can consult project-level summaries. */
  file?: ParsedFile;
  /**
   * Bindings a terminating guard *tested*, whether or not the test was strong enough to
   * clear them: `if (!NAME.test(name)) return null`.
   *
   * Within the function nothing changes — a guard this model cannot prove sufficient does
   * not clear anything. Across a call boundary it matters: a value the code deliberately
   * validated is not raw caller data the engine *observed*, and handing it to a second
   * function as if it were is how an earlier widening invented a flow. See
   * `engine/observed.ts`.
   */
  validated?: Set<string>;
  /**
   * What schema validation established in this function: bindings holding a parse result
   * (`const data = Body.parse(req.body)`), and inputs a terminating guard validated in place
   * (`if (!Body.safeParse(req.body).success) return`). A field the schema constrains is not
   * caller *text*; an open field still is. `engine/validation.ts`.
   */
  schemaFacts?: (SchemaFacts & { views: Map<string, SchemaView>; guards: Map<string, SchemaShape> }) | undefined;
}

export interface AnalyzeOptions {
  /**
   * Ignore every seed the project recorded for this function and use only `seeds`.
   * Used to summarise what a function does with one argument in isolation.
   */
  isolate?: boolean;
  /** Extra parameter seeds, `index -> origin`. */
  seeds?: Map<number, string>;
}

/**
 * Every name a binding pattern introduces, following renames, defaults, rest
 * elements, and nesting. A rename (`{ q: term }`) binds `term`, and missing that is
 * the same as missing the flow.
 */
function boundNames(pattern: ts.BindingName): string[] {
  if (ts.isIdentifier(pattern)) return [pattern.text];
  const names: string[] = [];
  for (const element of pattern.elements) {
    if (ts.isOmittedExpression(element)) continue;
    names.push(...boundNames(element.name));
  }
  return names;
}

function rootIdentifier(expression: ts.Node): string | null {
  if (ts.isIdentifier(expression)) return expression.text;
  if (ts.isPropertyAccessExpression(expression)) return rootIdentifier(expression.expression);
  if (ts.isElementAccessExpression(expression)) return rootIdentifier(expression.expression);
  if (ts.isCallExpression(expression)) return rootIdentifier(expression.expression);
  if (ts.isAwaitExpression(expression)) return rootIdentifier(expression.expression);
  // `yield* getSomething()` is the generator spelling of `await`, and until 2026-08-24
  // the engine unwrapped one and not the other — so an Effect handler, where every
  // read of the request is a `yield*`, lost its taint at the first statement.
  if (ts.isYieldExpression(expression) && expression.expression) return rootIdentifier(expression.expression);
  if (ts.isNonNullExpression(expression) || ts.isParenthesizedExpression(expression)) {
    return rootIdentifier(expression.expression);
  }
  // `(request.query as { sort?: string }).sort` — Fastify types `request.query` as
  // `unknown`, so its own documentation reads a query parameter through an
  // assertion. Unwrapping `await`, `yield*`, `!` and parentheses but not `as` meant
  // the root of that expression was nothing, and the value was not caller data.
  if (ts.isAsExpression(expression) || ts.isSatisfiesExpression(expression) || ts.isTypeAssertionExpression(expression)) {
    return rootIdentifier(expression.expression);
  }
  return null;
}

/** Is this expression a direct read of caller-controlled data? */
/** `await x` and `(x)` off an expression, for reading what was called. */
function unwrapAwait(node: ts.Node): ts.Node {
  let current = node;
  for (let depth = 0; depth < 4; depth += 1) {
    if (ts.isAwaitExpression(current) || ts.isParenthesizedExpression(current) || ts.isAsExpression(current)) {
      current = current.expression;
      continue;
    }
    return current;
  }
  return current;
}

function directTaintOrigin(node: ts.Node, requestParams: Set<string>, accessors?: Set<string>): string | null {
  /*
   * A type assertion is transparent here.
   *
   * `getQuery(event).slug as string` and `(request.query as Q).sort` are the ordinary
   * TypeScript spellings — `getQuery` returns `QueryObject` and Fastify types
   * `request.query` as `unknown`, so the cast is not optional decoration, it is how
   * the value is used at all. Unwrapping it at the entry point rather than in each
   * branch, because every branch below wants the same answer.
   */
  if (ts.isAsExpression(node) || ts.isSatisfiesExpression(node) || ts.isTypeAssertionExpression(node)) {
    return directTaintOrigin(node.expression, requestParams, accessors);
  }
  if (ts.isPropertyAccessExpression(node)) {
    /*
     * `new URL(request.url).searchParams` — the query string of every Web-standard
     * handler.
     *
     * `rootIdentifier` walks down to an identifier and a `new` expression has none,
     * so this whole shape had no origin. It only mattered when the object was bound
     * to a name first:
     *
     *     const params = new URL(request.url).searchParams;
     *     const sort = params.get("sort") ?? "rank";      // was untainted
     *
     * Chained in one expression it was already found, and `const u = new
     * URL(request.url); u.searchParams.get(…)` was found, so the gap was the two
     * lines in between — which is how the Next, Hono, Workers, Deno and Remix
     * documentation all write it, because `request.url` is a string and `URL` is
     * the only way to parse it.
     *
     * The URL's argument still has to be caller-derived, so `new URL(config.base)`
     * stays clean.
     */
    const base = bareExpression(node.expression);
    if (ts.isNewExpression(base) && /^URL(SearchParams)?$/.test(expressionName(base.expression))) {
      const first = base.arguments?.[0];
      const argumentRoot = first ? rootIdentifier(first) : null;
      if (argumentRoot && requestParams.has(argumentRoot) && REQUEST_PROPERTIES.has(node.name.text)) {
        return `${expressionName(node)} (caller-controlled request data)`;
      }
    }
    const name = expressionName(node);
    /*
     * A field read off something that is already caller data is caller data.
     *
     *     getQuery(event).name          // was lost
     *     readBody(event).name          // was lost
     *     const q = getQuery(event); q.name   // was found
     *
     * The branch below asks whether the *root identifier* is a request parameter,
     * and for `getQuery(event).name` the root is `getQuery`, not `event` — so the
     * origin was never found, while the same value bound to a name one line earlier
     * was. `getQuery` returns an object, so reading a property off it is the only
     * way to use it: this made the ordinary spelling of "what did the caller send"
     * invisible in every Nuxt server route, and `readBody` the same.
     *
     * Written as one recursive step rather than another special case, because this
     * is the second time the shape has appeared — `new URL(request.url).searchParams`
     * was the first, and special-casing it did not prevent the recurrence.
     *
     * Restricted to a **call** as the base, which is what an accessor is. Recursing
     * on any origin instead was tried and rejected: it turned
     * `event.context.session.tenantId` — the authenticated subject a Nitro middleware
     * attached — into caller data, because the `event.context` chain is itself a
     * request read. A property off a request *object* is already handled below, and
     * `isServerAttached` guards it; a property off an accessor *call* is what was
     * missing.
     */
    const accessed = unwrapAwait(node.expression);
    if (ts.isCallExpression(accessed) && !isServerAttached(name)) {
      const base = directTaintOrigin(accessed, requestParams, accessors);
      if (base) return `${name} (caller-controlled request data)`;
    }
    const root = rootIdentifier(node);
    if (root && requestParams.has(root)) {
      const property = node.name.text;
      // Only the property read directly off the request object belongs to the
      // server. `request.user` is the authenticated subject the auth layer
      // attached; `request.body.user` is a field the caller sent and named. The
      // deeper segments are the caller's own vocabulary, and treating them as
      // trusted loses every flow through a field called `state`, `account`,
      // `subject`, or `identity` — all of which are ordinary request-body names.
      if (isServerAttached(name)) return null;
      if (REQUEST_PROPERTIES.has(property)) return `${name} (caller-controlled request data)`;
      // req.body.field, req.query.q and friends.
      const parentName = expressionName(node.expression);
      for (const property2 of REQUEST_PROPERTIES) {
        if (parentName.endsWith(`.${property2}`)) return `${name} (caller-controlled request data)`;
      }
    }
    if (name === "process.argv") return "process.argv (command-line input)";
  }

  if (ts.isElementAccessExpression(node)) {
    const root = rootIdentifier(node);
    if (root && requestParams.has(root)) return `${expressionName(node)} (caller-controlled request data)`;
  }

  if (ts.isCallExpression(node)) {
    const name = calleeName(node);
    const tail = calleeTail(node);
    // `getQuery(event)` — a bare function that takes the request object and
    // returns what the caller sent. Requiring the request object as an argument
    // is what keeps this precise: a project's own `getQuery(connection)` is
    // untouched.
    if (accessors && accessors.size > 0 && ts.isIdentifier(node.expression) && accessors.has(node.expression.text)) {
      const first = node.arguments[0];
      const receiver = first ? rootIdentifier(first) : null;
      if (receiver && requestParams.has(receiver)) {
        return `${name}(${receiver}) (caller-controlled request data)`;
      }
    }
    /*
     * A namespaced accessor: `HttpServerRequest.schemaSearchParams(Schema)`.
     *
     * The form above requires a bare function handed the request object, which is
     * what keeps h3's `getQuery(event)` from matching a project's own
     * `getQuery(connection)`. Effect's accessors cannot satisfy either half — they
     * are reached through a namespace and their argument is a schema, because the
     * request is supplied by the effect context rather than passed in. So the tail is
     * matched instead, and the precision comes from the set being per-entry-point:
     * `schemaBodyJson` means nothing in a file no Effect adapter claimed.
     */
    if (accessors && accessors.size > 0 && ts.isPropertyAccessExpression(node.expression) && accessors.has(tail)) {
      return `${name}() (caller-controlled request data)`;
    }
    for (const candidate of TAINTED_CALLS) {
      if (name === candidate || name.endsWith(`.${candidate}`)) return `${name}() (caller-controlled request data)`;
    }
    const receiver = rootIdentifier(node.expression);
    if (receiver && requestParams.has(receiver) && TAINTED_BODY_READERS.has(tail)) {
      return `${name}() (caller-controlled request body)`;
    }
    if (receiver && requestParams.has(receiver) && (tail === "get" || tail === "header")) {
      return `${name}() (caller-controlled request header)`;
    }
    if (receiver && requestParams.has(receiver) && CONTEXT_ACCESSORS.has(tail)) {
      return `${name}() (caller-controlled request data)`;
    }
  }

  // Every one of these forwards `accessors`. Two of them used to drop it, so an
  // accessor-based framework lost its taint the moment the value was awaited or
  // cast — `(await readBody(event)).name` being the shape that mattered.
  if (ts.isAwaitExpression(node)) return directTaintOrigin(node.expression, requestParams, accessors);
  if (ts.isYieldExpression(node) && node.expression) return directTaintOrigin(node.expression, requestParams, accessors);
  if (ts.isParenthesizedExpression(node)) return directTaintOrigin(node.expression, requestParams, accessors);
  if (ts.isNonNullExpression(node)) return directTaintOrigin(node.expression, requestParams, accessors);
  return null;
}

/** Function parameters that look like the inbound request for this handler. */
function requestParameters(fn: ts.Node): Set<string> {
  const names = new Set<string>();
  const parameters = (fn as ts.FunctionLikeDeclaration).parameters ?? ts.factory.createNodeArray([]);
  for (const parameter of parameters) {
    if (ts.isIdentifier(parameter.name) && REQUEST_PARAMETER_NAMES.has(parameter.name.text)) {
      names.add(parameter.name.text);
      continue;
    }
    // A parameter annotated FormData or Request is caller data whatever it is
    // called, which is more reliable than any name list.
    if (ts.isIdentifier(parameter.name) && parameter.type) {
      const typeName = parameter.type.getText().replace(/<.*>$/, "").trim();
      if (REQUEST_PARAMETER_TYPES.test(typeName)) {
        names.add(parameter.name.text);
        continue;
      }
    }
    // Destructured route props and procedure arguments: ({ params, searchParams })
    // in a route handler, ({ ctx, input }) in a tRPC procedure. A renamed binding
    // is followed, because `{ input: payload }` is the same value under a new name.
    if (ts.isObjectBindingPattern(parameter.name)) {
      for (const element of parameter.name.elements) {
        const sourceName = element.propertyName && ts.isIdentifier(element.propertyName)
          ? element.propertyName.text
          : ts.isIdentifier(element.name)
            ? element.name.text
            : null;
        if (!sourceName) continue;
        if (!REQUEST_PROPERTIES.has(sourceName) && !REQUEST_PARAMETER_NAMES.has(sourceName)) continue;
        for (const bound of boundNames(element.name)) names.add(bound);
      }
    }
  }
  return names;
}

/**
 * Build the taint picture for one function body: which local bindings hold
 * caller-controlled data, and which of those a guard has since made safe.
 */
/** The name a function is known by, for looking it up in the cross-file index. */
function functionNameOf(fn: ts.Node): string {
  const named = fn as ts.FunctionLikeDeclaration;
  if (named.name && ts.isIdentifier(named.name)) return named.name.text;
  // `export const handler = async (…) => {}` and `const svc = { method() {} }`.
  const parent = fn.parent;
  if (parent && ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) return parent.name.text;
  if (parent && ts.isPropertyAssignment(parent) && ts.isIdentifier(parent.name)) return parent.name.text;
  return "";
}

export function analyzeFunction(file: ParsedFile, fn: ts.Node, options: AnalyzeOptions = {}): TaintScope {
  // An entry point knows things about its own handler that no general rule can
  // infer: that a NestJS `@Param("id") id` is caller data although it is an
  // ordinary string parameter, that an Electron `event` is the runtime's and not
  // the renderer's, and that h3 hands input over through free functions.
  const entry = entryPointForFunction(file, fn);
  const requestParams = requestParameters(fn);
  for (const trusted of entry?.trustedParameters ?? []) requestParams.delete(trusted);
  for (const seed of entry?.seeds ?? []) requestParams.add(seed.name);

  const scope: TaintScope = {
    fn,
    accessors: new Set(entry?.accessorFunctions ?? []),
    roots: new Map(),
    cleared: new Set(),
    htmlSafe: new Set(),
    htmlEscapers: htmlEscapersIn(file),
    allowlisted: new Set(),
    containmentChecked: new Set(),
    coerced: new Set(),
    clearedPaths: new Set(),
    taintedCollections: new Map(),
    initializers: new Map(),
    taintedPaths: new Map(),
    file,
    validated: new Set()
  };

  // A request parameter is itself a tainted root, so `req.query.q` used inline
  // (without a local binding) is still recognised.
  for (const name of requestParams) {
    scope.roots.set(name, { name, origin: `${name} (inbound request)`, declaration: fn });
  }
  // A seed's own wording is more precise than the generic one, so it wins.
  for (const seed of entry?.seeds ?? []) {
    scope.roots.set(seed.name, { name: seed.name, origin: seed.origin, declaration: fn });
  }

  /*
   * A parameter another file was observed handing caller data to.
   *
   * An entry point tells this function about its own handler. This tells it about a
   * function that is *not* a handler: the service method a controller delegates to,
   * which has no entry point and therefore no seeds, so nothing in it is caller data and
   * every rule judging a sink inside it stays silent. That is the shape three of
   * holdout-6's misses take.
   *
   * Seeded here rather than in each rule because the taint model is what nine of the ten
   * rule files consult. `file.observedParameters` records observation, never inference —
   * a real call site was seen passing an argument this engine could already prove was
   * caller-controlled *there* — which is the guard the earlier attempt at widening taint
   * was closed with.
   *
   * `trustedParameters` is applied above and wins: an adapter saying a binding is
   * server-supplied is a stronger statement than a call site's argument.
   */
  const observed = options.isolate ? undefined : file.observedParameters?.get(functionNameOf(fn));
  if (observed) {
    const parameters = (fn as ts.FunctionLikeDeclaration).parameters ?? [];
    for (const [index, origin] of observed) {
      const parameter = parameters[index];
      if (!parameter || !ts.isIdentifier(parameter.name)) continue;
      const name = parameter.name.text;
      if (entry?.trustedParameters?.includes(name)) continue;
      if (!scope.roots.has(name)) scope.roots.set(name, { name, origin, declaration: fn });
    }
  }

  /*
   * Parameters a resolved call site anywhere in the project was observed filling with
   * caller data — `engine/interproc.ts`, followed across modules and through as many calls
   * as its bounds allow. Keyed by this function's node, so it cannot be confused with a
   * namesake. The adapter's `trustedParameters` still win.
   */
  /*
   * The request parameter of a handler registered with a router or a server, by position:
   * `router.get("/x", (rq, rs) => …)` passes the request first whatever it is called.
   * `engine/handlers.ts`.
   */
  const contractual = options.isolate ? undefined : file.requestSeeds?.get(fn);
  if (contractual) {
    const parameters = (fn as ts.FunctionLikeDeclaration).parameters ?? [];
    for (const [index, origin] of contractual) {
      const parameter = parameters[index];
      if (!parameter) continue;
      for (const name of boundNames(parameter.name)) {
        if (entry?.trustedParameters?.includes(name)) continue;
        if (!scope.roots.has(name)) scope.roots.set(name, { name, origin, declaration: fn });
      }
    }
  }

  const seeded = options.isolate
    ? options.seeds
    : options.seeds
      ? new Map([...(file.parameterSeeds?.get(fn) ?? []), ...options.seeds])
      : file.parameterSeeds?.get(fn);
  const seededProperties = options.isolate ? undefined : file.propertySeeds?.get(fn);
  if (seeded || seededProperties) {
    const parameters = (fn as ts.FunctionLikeDeclaration).parameters ?? [];
    for (const [index, origin] of seeded ?? []) {
      const parameter = parameters[index];
      if (!parameter) continue;
      for (const name of boundNames(parameter.name)) {
        if (entry?.trustedParameters?.includes(name)) continue;
        if (!scope.roots.has(name)) scope.roots.set(name, { name, origin, declaration: fn });
      }
    }
    for (const [index, byProperty] of seededProperties ?? []) {
      const parameter = parameters[index];
      if (!parameter) continue;
      if (ts.isIdentifier(parameter.name)) {
        if (entry?.trustedParameters?.includes(parameter.name.text)) continue;
        for (const [property, origin] of byProperty) scope.taintedPaths!.set(`${parameter.name.text}.${property}`, origin);
        continue;
      }
      if (!ts.isObjectBindingPattern(parameter.name)) continue;
      for (const element of parameter.name.elements) {
        const key = element.propertyName && ts.isIdentifier(element.propertyName)
          ? element.propertyName.text
          : ts.isIdentifier(element.name)
            ? element.name.text
            : null;
        const origin = key ? byProperty.get(key) : undefined;
        if (!origin) continue;
        for (const name of boundNames(element.name)) {
          if (!scope.roots.has(name)) scope.roots.set(name, { name, origin, declaration: fn });
        }
      }
    }
  }

  const body = (fn as ts.FunctionLikeDeclaration).body;
  if (!body) return scope;

  if (mayValidateWithSchema(file)) {
    scope.schemaFacts = { resolve: file.resolveSchema ?? defaultSchemaResolver(), views: new Map(), guards: new Map() };
    collectSchemaGuards(body, scope);
  }

  /**
   * `let value; try { value = compute(x) }` binds `value` to that one expression.
   *
   * A declaration with no initialiser is invisible to `scope.initializers`, so every rule
   * that walks back from a binding to how it was built stops dead — and this shape is not
   * unusual, it is what any assignment inside a `try` looks like. A guard applied before the
   * assignment was therefore lost on exactly the handlers careful enough to use one.
   *
   * **Exactly one assignment.** A variable written twice cannot be resolved to a single
   * expression, and picking either one would state something the code does not say — the
   * value at the point of use might be from the other branch. Counting first and binding only
   * the unambiguous case is the difference between reading the code and guessing at it.
   */
  const assignmentsTo = new Map<string, ts.Expression[]>();
  walk(body, (node) => {
    if (!ts.isBinaryExpression(node)) return;
    if (node.operatorToken.kind !== ts.SyntaxKind.EqualsToken) return;
    if (!ts.isIdentifier(node.left)) return;
    const existing = assignmentsTo.get(node.left.text);
    if (existing) existing.push(node.right);
    else assignmentsTo.set(node.left.text, [node.right]);
  });

  const declaredEmpty = new Set<string>();
  walk(body, (node) => {
    if (!ts.isVariableDeclaration(node)) return;
    if (node.initializer || !ts.isIdentifier(node.name)) return;
    declaredEmpty.add(node.name.text);
  });

  /**
   * Bind every local that holds caller data.
   *
   * Run more than once, interleaved with collection analysis: a query string is
   * often assembled by pushing into an array and then reading the array back
   * out, and the declaration that reads it out can be written above the pushes
   * that taint it. One pass in declaration order sees the read before the write
   * and binds nothing, which loses the most common shape SQL injection actually
   * takes in real code.
   */
  const bindRoots = (): void => walk(body, (node) => {
    if (ts.isVariableDeclaration(node) && !node.initializer && ts.isIdentifier(node.name)) {
      const written = assignmentsTo.get(node.name.text);
      if (!written || written.length !== 1 || !declaredEmpty.has(node.name.text)) return;
      const only = written[0]!;
      scope.initializers.set(node.name.text, only);
      if (bindSchemaValue(node.name.text, only, node, scope, requestParams)) return;
      const origin = taintOrigin(only, scope, requestParams);
      if (origin) scope.roots.set(node.name.text, { name: node.name.text, origin, declaration: node });
      return;
    }

    if (ts.isVariableDeclaration(node) && node.initializer && ts.isIdentifier(node.name)) {
      scope.initializers.set(node.name.text, node.initializer);
      if (bindSchemaValue(node.name.text, node.initializer, node, scope, requestParams)) return;
      const origin = taintOrigin(node.initializer, scope, requestParams);
      if (origin) {
        scope.roots.set(node.name.text, { name: node.name.text, origin, declaration: node });
        return;
      }
      /*
       * `const where = { id: req.params.id, ownerId: req.user.id }` — an object literal
       * that holds caller data in some of its fields. The model reads no taint in an object
       * literal, so `where.id` was not caller data one line after it plainly was. Recorded
       * per field, so `where.ownerId` stays what it is; a spread of caller data makes the
       * whole object the caller's.
       */
      const literal = bareExpression(node.initializer);
      if (ts.isObjectLiteralExpression(literal)) {
        for (const property of literal.properties) {
          if (ts.isSpreadAssignment(property)) {
            const spread = taintOrigin(property.expression, scope, requestParams);
            if (spread) scope.roots.set(node.name.text, { name: node.name.text, origin: spread, declaration: node });
            continue;
          }
          const key = property.name && (ts.isIdentifier(property.name) || ts.isStringLiteral(property.name)) ? property.name.text : null;
          if (!key) continue;
          const value = ts.isPropertyAssignment(property)
            ? property.initializer
            : ts.isShorthandPropertyAssignment(property)
              ? property.name
              : null;
          if (!value) continue;
          const fieldOrigin = taintOrigin(value, scope, requestParams);
          if (fieldOrigin) scope.taintedPaths!.set(`${node.name.text}.${key}`, fieldOrigin);
        }
      }
      return;
    }

    /*
     * `for (const line of req.body.lines)` and `for (const key in req.query)`: the loop
     * variable is each element of the caller's collection.
     */
    if ((ts.isForOfStatement(node) || ts.isForInStatement(node)) && ts.isVariableDeclarationList(node.initializer)) {
      const origin = taintOrigin(node.expression, scope, requestParams);
      if (!origin) return;
      for (const declaration of node.initializer.declarations) {
        for (const bound of boundNames(declaration.name)) {
          scope.roots.set(bound, { name: bound, origin: `${origin}, each element`, declaration: node });
        }
      }
      return;
    }

    /*
     * `req.body.items.map((item) => …)`, `.forEach`, `.filter`, `.reduce`, `.then`: the
     * callback's parameter is an element of — or the resolution of — caller data. Bound
     * in this scope, because every rule judges a sink inside the callback against the
     * enclosing handler's picture.
     */
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
      const method = node.expression.name.text;
      const position = ELEMENT_CALLBACKS.get(method);
      if (position === undefined) return;
      const callback = node.arguments[0] ? bareExpression(node.arguments[0]) : undefined;
      if (!callback || !(ts.isArrowFunction(callback) || ts.isFunctionExpression(callback))) return;
      const parameter = callback.parameters[position];
      if (!parameter) return;
      const origin = taintOrigin(node.expression.expression, scope, requestParams);
      if (!origin) return;
      for (const bound of boundNames(parameter.name)) {
        if (!scope.roots.has(bound)) scope.roots.set(bound, { name: bound, origin: `${origin}, each element`, declaration: callback });
      }
      return;
    }

    // `const { status, customer } = req.query` is how most handlers actually read
    // their input. Without this every one of those flows stops at the declaration,
    // which is the difference between finding a query built from user data and
    // finding nothing at all.
    if (ts.isVariableDeclaration(node) && node.initializer && ts.isObjectBindingPattern(node.name)) {
      if (bindSchemaFields(node, node.name, scope, requestParams)) return;
      const origin = taintOrigin(node.initializer, scope, requestParams);
      if (!origin) {
        // `const { term } = options` where only `options.term` was handed caller data.
        const base = scope.taintedPaths && scope.taintedPaths.size > 0 ? dottedPath(node.initializer) : null;
        if (!base) return;
        for (const element of node.name.elements) {
          const key = element.propertyName && ts.isIdentifier(element.propertyName)
            ? element.propertyName.text
            : ts.isIdentifier(element.name)
              ? element.name.text
              : null;
          const path = key ? `${base}.${key}` : null;
          const seeded = path ? scope.taintedPaths!.get(path) : undefined;
          if (!seeded) continue;
          for (const bound of boundNames(element.name)) scope.roots.set(bound, { name: bound, origin: seeded, declaration: node });
        }
        return;
      }
      for (const bound of boundNames(node.name)) {
        scope.roots.set(bound, { name: bound, origin, declaration: node });
      }
      return;
    }
    if (ts.isVariableDeclaration(node) && node.initializer && ts.isArrayBindingPattern(node.name)) {
      const origin = taintOrigin(node.initializer, scope, requestParams);
      if (!origin) return;
      for (const bound of boundNames(node.name)) {
        scope.roots.set(bound, { name: bound, origin, declaration: node });
      }
      return;
    }
    if (
      ts.isBinaryExpression(node) &&
      node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
      ts.isIdentifier(node.left)
    ) {
      const origin = taintOrigin(node.right, scope, requestParams);
      if (origin) scope.roots.set(node.left.text, { name: node.left.text, origin, declaration: node });
    }
  });

  // Collections are analysed before the bindings as well as after. A query
  // string is often assembled by pushing into an array and then read back out
  // into a local, and the declaration that reads it out can be written above the
  // pushes that taint it — one pass in declaration order sees the read before
  // the write and binds nothing. The pre-pass only needs the request parameters,
  // which exist from the start, so it costs one walk and no accuracy.
  // Bindings and collections feed each other, so they alternate. A local bound
  // from the request makes a push into an array tainted; that array read back
  // out makes another local tainted. Two rounds settle every shape the corpus
  // contains and cost two walks of one function body.
  for (let round = 0; round < 2; round += 1) {
    collectAccumulators(body, scope, requestParams);
    bindRoots();
  }
  applyGuards(file, body, scope);
  return scope;
}

/**
 * Array and promise methods whose callback receives an element of the receiver, and the
 * position of that parameter: `reduce` hands the accumulator first.
 */
const ELEMENT_CALLBACKS = new Map<string, number>([
  ["map", 0],
  ["forEach", 0],
  ["filter", 0],
  ["flatMap", 0],
  ["find", 0],
  ["findLast", 0],
  ["some", 0],
  ["every", 0],
  ["reduce", 1],
  ["then", 0]
]);

/** Methods that put a value into a collection or a string builder. */
const ACCUMULATING_METHODS = new Set(["push", "unshift", "add", "append", "concat", "write", "set"]);

/** Methods that take the accumulated value back out as one string. */
const DRAINING_METHODS = new Set(["join", "toString", "flat", "flatMap", "map", "filter", "slice", "concat"]);

/**
 * Find collections that accumulate attacker-controlled data.
 *
 * Two passes, because order matters in the wrong direction: a value may be pushed
 * into an array on line 20 and the array may only be recognised as tainted by
 * something on line 40. Iterating until nothing changes costs almost nothing on a
 * function body and avoids depending on statement order.
 */
function collectAccumulators(body: ts.Node, scope: TaintScope, requestParams: Set<string>): void {
  for (let pass = 0; pass < 3; pass += 1) {
    let changed = false;
    walk(body, (node) => {
      if (!ts.isCallExpression(node)) return;
      if (!ts.isPropertyAccessExpression(node.expression)) return;
      const method = node.expression.name.text;
      if (!ACCUMULATING_METHODS.has(method)) return;
      const target = rootIdentifier(node.expression.expression);
      if (!target || scope.taintedCollections.has(target)) return;
      for (const argument of node.arguments) {
        const origin = taintOrigin(argument, scope, requestParams);
        if (!origin) continue;
        scope.taintedCollections.set(target, `${origin} via ${target}.${method}()`);
        changed = true;
        break;
      }
    });

    // An array literal built from tainted parts is the same thing written inline.
    walk(body, (node) => {
      if (!ts.isVariableDeclaration(node) || !ts.isIdentifier(node.name) || !node.initializer) return;
      if (!ts.isArrayLiteralExpression(node.initializer)) return;
      if (scope.taintedCollections.has(node.name.text)) return;
      for (const element of node.initializer.elements) {
        const origin = taintOrigin(element, scope, requestParams);
        if (!origin) continue;
        scope.taintedCollections.set(node.name.text, origin);
        changed = true;
        break;
      }
    });

    if (!changed) return;
  }
}

/**
 * The expression a local binding holds, following one level of aliasing.
 *
 * A rule asking "is this argument a SQL string" has to look past the variable
 * name: `pool.query(sql, values)` says nothing, while the template `sql` was built
 * from says everything.
 */
export function resolveExpression(node: ts.Node, scope: TaintScope): ts.Node {
  let current = node;
  for (let depth = 0; depth < 4; depth += 1) {
    if (!ts.isIdentifier(current)) return current;
    const initializer = scope.initializers.get(current.text) ?? moduleConstant(current);
    if (!initializer) return current;
    current = initializer;
  }
  return current;
}

/**
 * The text of an expression with its module-level string constants substituted.
 *
 * A rule that asks "does this look like SQL" by reading an expression's own text
 * is defeated by the most ordinary way a statement is written: the prologue in a
 * module constant, the variable parts appended in the handler. `[BASE_QUERY,
 * ...clauses].join("\n")` contains no SQL keyword until `BASE_QUERY` is read.
 *
 * Substitution is one level deep and only for literal initialisers at module
 * scope, so nothing that changes at runtime is ever folded in.
 */
export function expandedText(node: ts.Node, source: ts.SourceFile): string {
  let text = node.getText(source);
  const seen = new Set<string>();
  walk(node, (inner) => {
    if (!ts.isIdentifier(inner) || seen.has(inner.text)) return;
    seen.add(inner.text);
    const constant = moduleConstant(inner);
    if (constant) text += `\n${constant.getText(source)}`;
  });
  return text;
}

/**
 * A module-level constant with a literal initialiser.
 *
 * The prologue of a query is very often a module constant — `const BASE_QUERY =
 * "select … from customers where tenant_id = ?"` — with the variable parts
 * appended in the handler. A rule that asks "does this look like SQL" by reading
 * the expression's own text sees `[BASE_QUERY, ...clauses].join("\n")`, finds no
 * keyword, and declines to look further. Resolving the constant is what makes
 * that shape visible, and it is limited to literal initialisers at module scope
 * so it cannot follow anything that changes at runtime.
 */
function moduleConstant(identifier: ts.Identifier): ts.Expression | undefined {
  const source = identifier.getSourceFile();
  if (!source) return undefined;
  for (const statement of source.statements) {
    if (!ts.isVariableStatement(statement)) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (!ts.isIdentifier(declaration.name) || declaration.name.text !== identifier.text) continue;
      const initializer = declaration.initializer;
      if (!initializer) return undefined;
      return isConstantString(initializer) ? initializer : undefined;
    }
  }
  return undefined;
}

/** Why this expression is tainted, or null when it is not. */
export function taintOrigin(node: ts.Node, scope: TaintScope, requestParams?: Set<string>): string | null {
  const params = requestParams ?? new Set<string>();

  // A field a schema constrains — `Body.parse(req.body).id` with `id: z.string().uuid()`, or
  // `req.body.id` after a guard validated `req.body` — cannot carry text the caller chose.
  if (isSchemaConstrained(node, scope)) return null;

  const direct = directTaintOrigin(node, params, scope.accessors);
  if (direct) return direct;

  if (ts.isIdentifier(node)) {
    if (scope.cleared.has(node.text)) return null;
    const root = scope.roots.get(node.text);
    if (root) return root.origin;
    return scope.taintedCollections.get(node.text) ?? null;
  }

  if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
    const path = dottedPath(node);
    if (path && scope.clearedPaths.has(path)) return null;
    // `request.user.accountId` is the authenticated subject the auth layer
    // attached, not something the caller chose. `directTaintOrigin` already
    // refuses it; without the same refusal here the fallback below hands back
    // the request's origin anyway and every correctly scoped query looks like a
    // defect.
    if (path && isServerAttached(path)) return null;
    // `options.term` when only that property of `options` was handed caller data.
    if (path && scope.taintedPaths && scope.taintedPaths.size > 0) {
      for (const [prefix, origin] of scope.taintedPaths) {
        if (path === prefix || path.startsWith(`${prefix}.`)) return origin;
      }
    }
    const root = rootIdentifier(node);
    if (root && !scope.cleared.has(root) && scope.roots.has(root)) return scope.roots.get(root)!.origin;
    /*
     * A field read off something already tainted is tainted, however that something
     * was written.
     *
     *     const q = getQuery(event); const wanted = q.name   // found
     *     const wanted = getQuery(event).name                // was NOT found
     *
     * Both read the same field of the same object. The first works because `q` becomes
     * a tainted root — the model assumes a function handed caller data returns
     * something influenced by it — and the check above resolves a property access
     * through its root *identifier*. The second has no identifier to resolve: for
     * `getQuery(event).name` the root is `getQuery`, which is not a binding.
     *
     * So the base expression is asked directly. That reaches every accessor shape at
     * once instead of one at a time — `getQuery(event).name` and
     * `(await readBody(event)).name` are the Nuxt and h3 spellings, and the same shape
     * had already been special-cased once for `new URL(request.url).searchParams`
     * before recurring here, which is what argued for doing it generally.
     *
     * `isServerAttached` is checked above and still has the last word, so
     * `event.context.session.tenantId` stays server-derived. A bare identifier base is
     * excluded because the root check already answered it.
     */
    // `unwrapAwait`, not `bareExpression`: `(await readBody(event)).name` is the
    // documented h3 spelling for reading a request body, and its base is an await
    // wrapped in parentheses rather than a bare call.
    const base = unwrapAwait(node.expression);
    /*
     * Only a **call** base is worth asking about, and the reason is cost.
     *
     * Recursing on any non-identifier base measured at 1.71x on a 72KB file and
     * tripped the performance gate: property chains are everywhere, and for `a.b.c.d`
     * the walk down to `a` learns nothing the root check above did not already answer.
     * A call is the one base with no identifier root to resolve, which is exactly why
     * this case was missing in the first place.
     */
    if (ts.isCallExpression(base)) {
      const origin = taintOrigin(base, scope, params);
      if (origin) return origin;
    }
    return null;
  }

  if (ts.isTemplateExpression(node) || ts.isBinaryExpression(node)) {
    for (const part of dynamicParts(node)) {
      const origin = taintOrigin(part, scope, params);
      if (origin) return origin;
    }
    return null;
  }

  if (ts.isCallExpression(node)) {
    const name = calleeName(node);
    const tail = calleeTail(node);
    // `clauses.join(" AND ")` hands back everything that was pushed into it.
    if (DRAINING_METHODS.has(tail) && ts.isPropertyAccessExpression(node.expression)) {
      const receiver = node.expression.expression;
      const collection = rootIdentifier(receiver);
      if (collection) {
        const accumulated = scope.taintedCollections.get(collection);
        if (accumulated) return accumulated;
      }
      // `[BASE, ...clauses.map(wrap), ordering].join("\n")` — the array is
      // assembled at the call site rather than named, which is how a statement
      // built from a fixed prologue plus optional clauses is usually written.
      // Only a drained array literal is examined, never every array literal: a
      // correctly parameterised builder puts placeholders in its clause array and
      // the caller's values in a separate bind array, and treating any array that
      // has ever seen a request value as tainted flags exactly that shape.
      if (ts.isArrayLiteralExpression(receiver)) {
        for (const element of receiver.elements) {
          const inner = ts.isSpreadElement(element) ? element.expression : element;
          const origin = taintOrigin(inner, scope, params);
          if (origin) return origin;
        }
      }
    }
    if (UNIVERSAL_SANITIZERS.has(name)) return null;
    /*
     * `ALLOWED.get(whatever the caller sent)` returns one of the table's own literals.
     *
     * `applyGuards` already cleared the *binding* this is assigned to, and that was not
     * enough: a sink resolves an interpolated identifier back through
     * `scope.initializers` and re-derives taint from the expression, so the clearing was
     * bypassed and the reported flow read "taint from params via SORTABLE_COLUMNS.get()"
     * — naming the sanitiser as the conduit. A constant-table read is a sanitiser like
     * any other, so it belongs here beside them rather than only at the binding.
     */
    if (readsConstantTable(node, node.getSourceFile())) return null;
    if (HTML_ESCAPERS.has(name) || HTML_ESCAPERS.has(tail)) return null;
    // A helper in this file whose body escapes clears taint exactly as a named
    // escaper does. This is the gate that matters: without it the value stays
    // tainted through the call and the layered output check reports the handler
    // even while reporting that every interpolated part *was* escaped.
    if (scope.htmlEscapers.has(name) || scope.htmlEscapers.has(tail)) return null;
    if (PASS_THROUGH_CALLS.has(name) || PASS_THROUGH_CALLS.has(tail)) {
      const receiver = ts.isPropertyAccessExpression(node.expression) ? node.expression.expression : null;
      if (receiver) {
        const origin = taintOrigin(receiver, scope, params);
        if (origin) return origin;
      }
      for (const argument of node.arguments) {
        const origin = taintOrigin(argument, scope, params);
        if (origin) return origin;
      }
      return null;
    }
    // An unknown function that receives attacker-controlled data is assumed to
    // return data influenced by it. A body parser, a normaliser, or any project
    // helper would otherwise break the chain, and losing the flow through
    // `const body = await readBody(req)` would miss most real handlers.
    //
    // A *project* function is not unknown: its body has been read, and when none of its
    // returns carries this argument -- a validator returning a vetted constant, a parser
    // returning a number -- the assumption is replaced by what the body says.
    // `engine/summaries.ts`.
    for (let index = 0; index < node.arguments.length; index += 1) {
      const origin = taintOrigin(node.arguments[index]!, scope, params);
      if (!origin) continue;
      const summary = scope.file?.returnSummary?.(node, index);
      if (summary && !summary.tainted) continue;
      return `${origin} via ${name || tail}()`;
    }
    // A method called on a tainted receiver also yields tainted data.
    if (ts.isPropertyAccessExpression(node.expression)) {
      const receiverOrigin = taintOrigin(node.expression.expression, scope, params);
      if (receiverOrigin) return receiverOrigin;
    }
    return null;
  }

  if (ts.isNewExpression(node) && expressionName(node.expression) === "URL") {
    for (const argument of node.arguments ?? []) {
      const origin = taintOrigin(argument, scope, params);
      if (origin) return origin;
    }
    return null;
  }

  if (
    ts.isAwaitExpression(node) ||
    (ts.isYieldExpression(node) && node.expression !== undefined) ||
    ts.isParenthesizedExpression(node) ||
    ts.isNonNullExpression(node) ||
    ts.isAsExpression(node) ||
    ts.isSatisfiesExpression(node) ||
    ts.isTypeAssertionExpression(node) ||
    ts.isExpressionWithTypeArguments(node)
  ) {
    // A type assertion changes nothing at runtime. `(await request.json()) as Body`
    // is exactly as attacker-controlled as the call it wraps, and stopping here was
    // silently ending every flow in a TypeScript codebase.
    return node.expression ? taintOrigin(node.expression, scope, params) : null;
  }

  if (ts.isConditionalExpression(node)) {
    return taintOrigin(node.whenTrue, scope, params) ?? taintOrigin(node.whenFalse, scope, params);
  }

  return null;
}

/**
 * Does this regular expression constrain the *whole* value to something that cannot
 * traverse or inject?
 *
 * Anchored at both ends, and containing none of the characters that make a path or a
 * command dangerous. Deliberately conservative: it answers only when the answer is
 * certain, and an unreadable pattern is treated as no guard at all rather than
 * guessed at.
 */
function constrainsWholeValue(literal: string): boolean {
  const match = /^\/(.*)\/[a-z]*$/s.exec(literal);
  const body = match?.[1];
  if (body === undefined) return false;
  if (!body.startsWith("^") || !body.endsWith("$")) return false;

  const inner = body.slice(1, -1);
  // An alternation escapes the anchors: `^a$|^../..` is anchored and unsafe.
  if (inner.includes("|")) return false;

  /*
   * Drop escape pairs first. `\d`, `\w`, `\s` and `\.` are either class shorthands
   * or a literal dot, and none can match a separator on its own — so removing them
   * leaves exactly the characters the pattern admits verbatim.
   */
  const bare = inner.replace(/\\./g, "");

  /*
   * `.` is any character, so `^.*$` is anchored and constrains nothing — the first
   * version of this predicate accepted it, which is the failure worth naming. The
   * rest are the characters that make a path or a command dangerous.
   */
  return !/[.\/\\"'`;&$]/.test(bare);
}


/**
 * Is this conditional an allowlist gate that yields either a vetted value or a
 * constant?
 *
 * Both polarities occur and both are safe:
 *
 *     ALLOWED.has(x) ? x : "default"
 *     !ALLOWED.has(x) ? "default" : x
 */
/** Parentheses and type assertions off an expression. */
function bareExpression(node: ts.Node): ts.Node {
  let current = node;
  for (let depth = 0; depth < 6; depth += 1) {
    if (ts.isParenthesizedExpression(current) || ts.isAsExpression(current) || ts.isNonNullExpression(current)) {
      current = current.expression;
      continue;
    }
    return current;
  }
  return current;
}

/**
 * Is every value in this object literal a literal the source pins?
 *
 * Nested objects are refused rather than walked: one level is what a lookup table
 * is, and anything deeper is a configuration tree whose leaves this pass has not
 * established the origin of.
 */
function isLiteralTable(object: ts.ObjectLiteralExpression): boolean {
  if (object.properties.length === 0) return false;
  return object.properties.every((property) => {
    if (!ts.isPropertyAssignment(property)) return false;
    const value = bareExpression(property.initializer);
    return (
      ts.isStringLiteralLike(value) ||
      ts.isNumericLiteral(value) ||
      value.kind === ts.SyntaxKind.TrueKeyword ||
      value.kind === ts.SyntaxKind.FalseKeyword
    );
  });
}

/**
 * The constant lookup tables this file declares, by name.
 *
 * Built once per file. The obvious implementation walks the whole source looking for
 * the declaration each time a `table[key]` is seen, which is quadratic in a large
 * file — the same shape that cost this engine 25x on a repository scan and was
 * re-introduced twice more before this comment existed. If a new lookup wants the
 * declarations of a file, index them; do not walk.
 */
const CONSTANT_TABLES = new WeakMap<ts.SourceFile, Set<string>>();

function constantTablesIn(source: ts.SourceFile): Set<string> {
  const cached = CONSTANT_TABLES.get(source);
  if (cached) return cached;
  const names = new Set<string>();
  walk(source, (node) => {
    if (!ts.isVariableDeclaration(node) || !ts.isIdentifier(node.name) || !node.initializer) return;
    const list = node.parent;
    if (!ts.isVariableDeclarationList(list) || (list.flags & ts.NodeFlags.Const) === 0) return;
    const initializer = bareExpression(node.initializer);
    if (ts.isObjectLiteralExpression(initializer) && isLiteralTable(initializer)) names.add(node.name.text);
    // `new Map([["scheduled", "j.scheduled_for"], …])` is the same allowlist written the
    // other way, and it is the way a TypeScript codebase tends to write it, because a Map
    // types its keys. Reading only the object-literal form meant a correctly written
    // sort-column allowlist read as caller-controlled: the engine reported an ORDER BY
    // that cannot be anything but one of four constants.
    if (isLiteralMap(initializer)) names.add(node.name.text);
  });
  CONSTANT_TABLES.set(source, names);
  return names;
}

/**
 * `new Map([[k, v], …])` or `new Set([…])` whose every entry is a literal.
 *
 * A `Set` counts because `ALLOWED.has(x) ? x : fallback` is the membership form of the
 * same guard, and `allowlistedTernary` below already understands that shape — it just
 * had no way to know the set was constant.
 */
function isLiteralMap(node: ts.Node): boolean {
  if (!ts.isNewExpression(node)) return false;
  const constructed = ts.isIdentifier(node.expression) ? node.expression.text : null;
  if (constructed !== "Map" && constructed !== "Set") return false;
  const entries = node.arguments?.[0];
  if (!entries || !ts.isArrayLiteralExpression(entries) || entries.elements.length === 0) return false;
  return entries.elements.every((element) => {
    const bare = bareExpression(element);
    if (constructed === "Set") return isConstantString(bare) || ts.isNumericLiteral(bare);
    if (!ts.isArrayLiteralExpression(bare) || bare.elements.length !== 2) return false;
    return bare.elements.every((part) => {
      const value = bareExpression(part);
      return isConstantString(value) || ts.isNumericLiteral(value);
    });
  });
}

/** Does this `table[key]` read from a constant table declared in this file? */
function indexesConstantTable(access: ts.ElementAccessExpression, source: ts.SourceFile): boolean {
  const table = bareExpression(access.expression);
  return ts.isIdentifier(table) && constantTablesIn(source).has(table.text);
}

/**
 * `TABLE.get(whateverTheCallerSent)` against a constant table.
 *
 * The element-access form `TABLE[key]` was understood and the method form was not, so
 * whether a correctly-guarded value read as safe depended on which of the two the author
 * had reached for. A `Map` cannot be indexed with brackets, so choosing a `Map` — the
 * better-typed choice — silently lost the guard.
 */
function readsConstantTable(call: ts.CallExpression, source: ts.SourceFile): boolean {
  if (!ts.isPropertyAccessExpression(call.expression)) return false;
  const tail = call.expression.name.text;
  if (tail !== "get" && tail !== "has") return false;
  const table = bareExpression(call.expression.expression);
  return ts.isIdentifier(table) && constantTablesIn(source).has(table.text);
}

function allowlistedTernary(node: ts.ConditionalExpression): boolean {
  let condition: ts.Node = node.condition;
  let negated = false;
  while (ts.isPrefixUnaryExpression(condition) && condition.operator === ts.SyntaxKind.ExclamationToken) {
    negated = !negated;
    condition = condition.operand;
  }
  if (ts.isParenthesizedExpression(condition)) condition = condition.expression;
  if (!ts.isCallExpression(condition)) return false;

  const tail = calleeTail(condition);
  if (tail !== "has" && tail !== "includes" && tail !== "hasOwnProperty") return false;

  const tested = condition.arguments[0] ? rootIdentifier(condition.arguments[0]!) : null;
  if (!tested) return false;

  const vetted = negated ? node.whenFalse : node.whenTrue;
  const fallback = negated ? node.whenTrue : node.whenFalse;
  return rootIdentifier(vetted) === tested && isConstantString(fallback);
}

/**
 * Every function declared in this file whose **body** HTML-escapes, by name.
 *
 * The defect this closes, isolated to a single variable: a textbook escaper — a
 * `.replace` chain over `&`, `<`, `>`, `"` — was recognised if and only if its
 * **name** matched `HTML_ESCAPERS`. Called `escapeHtml` it was a guard; the same
 * function called `toSafeHtml`, `harden` or `fmt` was not, and the correctly written
 * handler using it was reported for reflected XSS. The chain was already understood
 * one line up, in `const safe = dirty.replace(/[&<>]/g, …)`, and lost the moment a
 * developer did the ordinary thing and extracted it into a helper.
 *
 * So: read the body instead of the name. Structural, and therefore not something a
 * project's house style can defeat.
 *
 * Deliberately narrow, because this only ever *silences* a finding and the cost of
 * being wrong is a false negative:
 *
 *  - the callee must resolve to a function in this file, so nothing is assumed about
 *    a helper the engine cannot read;
 *  - the chain must cover both `<` and `&`, which is the minimum that makes markup
 *    inert — escaping `<` alone leaves `&lt;` forgeable through a double-encode, and
 *    a partial escaper is not a guard;
 *  - the escaped value must be what the function gives back, so a function that
 *    escapes into a log line and returns the raw input is not mistaken for a guard.
 */
const ESCAPER_CACHE = new WeakMap<ParsedFile, Set<string>>();

/** Memoized, because three separate rules ask the same question per file. */
export function htmlEscapersIn(file: ParsedFile): Set<string> {
  const cached = ESCAPER_CACHE.get(file);
  if (cached) return cached;
  const computed = localHtmlEscapers(file);
  ESCAPER_CACHE.set(file, computed);
  return computed;
}

function localHtmlEscapers(file: ParsedFile): Set<string> {
  const names = new Set<string>();
  const consider = (name: string | undefined, fn: ts.FunctionLikeDeclaration) => {
    if (!name || !fn.body) return;
    /*
     * A concise arrow — `const esc = (v) => v.replace(...)` — has no return
     * statement, and it is the shape a one-line escaper is almost always written
     * in. Looking only for `ReturnStatement` missed every one of them.
     */
    if (!ts.isBlock(fn.body)) {
      if (coversMarkup(fn.body, file)) names.add(name);
      return;
    }
    let escapes = false;
    walk(fn.body, (node) => {
      if (escapes) return;
      if (!ts.isReturnStatement(node) || !node.expression) return;
      escapes = coversMarkup(node.expression, file);
    });
    if (escapes) names.add(name);
  };
  walk(file.source, (node) => {
    if (ts.isFunctionDeclaration(node)) consider(node.name?.text, node);
    else if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      node.initializer &&
      (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer))
    ) {
      consider(node.name.text, node.initializer);
    }
  });
  return names;
}

/** A `.replace` chain, in a returned expression, that neutralises `<` and `&`. */
function coversMarkup(expression: ts.Node, file: ParsedFile): boolean {
  const covered = new Set<string>();
  let node: ts.Node = expression;
  for (let depth = 0; depth < 12; depth += 1) {
    if (!ts.isCallExpression(node)) break;
    const tail = calleeTail(node);
    if (tail !== "replace" && tail !== "replaceAll") break;
    const pattern = node.arguments[0];
    const replacement = node.arguments[1];
    if (pattern && replacement && producesEntities(replacement, file)) {
      const text = ts.isRegularExpressionLiteral(pattern) || ts.isStringLiteral(pattern) ? pattern.getText() : "";
      for (const character of ["&", "<", ">", '"', "'"]) if (text.includes(character)) covered.add(character);
    }
    if (!ts.isPropertyAccessExpression(node.expression)) break;
    node = node.expression.expression;
  }
  return covered.has("<") && covered.has("&");
}

/** `"&lt;"`, `"&amp;"`, `"&#39;"` — a replacement that makes markup inert. */
/**
 * Names of constant tables in this file whose every value is a markup entity.
 *
 * `{ "&": "&amp;", "<": "&lt;", ">": "&gt;" }` is a character-to-entity map and
 * nothing else, so a replacement that indexes one produces entities.
 */
const ENTITY_TABLES = new WeakMap<ts.SourceFile, Set<string>>();

function entityTablesIn(file: ParsedFile): Set<string> {
  const cached = ENTITY_TABLES.get(file.source);
  if (cached) return cached;
  const names = new Set<string>();
  walk(file.source, (node) => {
    if (!ts.isVariableDeclaration(node) || !ts.isIdentifier(node.name) || !node.initializer) return;
    const initializer = bareExpression(node.initializer);
    if (!ts.isObjectLiteralExpression(initializer) || initializer.properties.length === 0) return;
    const all = initializer.properties.every(
      (property) => ts.isPropertyAssignment(property) && isMarkupEntity(bareExpression(property.initializer))
    );
    if (all) names.add(node.name.text);
  });
  ENTITY_TABLES.set(file.source, names);
  return names;
}

/**
 * Does this `.replace` replacement produce HTML entities?
 *
 * Either it is one — `"&amp;"` — or it is a function that looks one up in a table
 * of them:
 *
 *     const HTML_ENTITIES = { "&": "&amp;", "<": "&lt;", ">": "&gt;" };
 *     value.replace(/[&<>"']/g, (char) => HTML_ENTITIES[char])
 *
 * That is the commonest way anyone writes an escaper, and reading only literal
 * replacements meant this one was recognised by its *name* instead — so the
 * mutation harness, which renames local functions, turned a correctly escaped
 * page into a reported cross-site-scripting defect. Recognising the table is what
 * makes the recognition survive a rename.
 */
function producesEntities(node: ts.Node, file: ParsedFile): boolean {
  if (isMarkupEntity(node)) return true;
  const inner = bareExpression(node);
  if (!ts.isArrowFunction(inner) && !ts.isFunctionExpression(inner)) return false;
  const tables = entityTablesIn(file);
  if (tables.size === 0) return false;
  let found = false;
  const check = (expression: ts.Node): void => {
    const bare = bareExpression(expression);
    if (!ts.isElementAccessExpression(bare)) return;
    const table = bareExpression(bare.expression);
    if (ts.isIdentifier(table) && tables.has(table.text)) found = true;
  };
  if (!ts.isBlock(inner.body)) check(inner.body);
  else {
    walk(inner.body, (statement) => {
      if (found || !ts.isReturnStatement(statement) || !statement.expression) return;
      check(statement.expression);
    });
  }
  return found;
}

function isMarkupEntity(node: ts.Node): boolean {
  if (!ts.isStringLiteral(node) && !ts.isNoSubstitutionTemplateLiteral(node)) return false;
  return /^&(?:[a-z]+|#x?[0-9a-f]+);$/i.test(node.text);
}


/**
 * Recognise the guards that genuinely make a tainted value safe.
 *
 * This is the half of the engine that prevents false positives. A correctly
 * written allowlist check, containment check, or escaping call must clear the
 * taint, or every well-written codebase drowns in noise.
 */
function applyGuards(file: ParsedFile, body: ts.Node, scope: TaintScope): void {
  walk(body, (node) => {
    // `const safe = escapeHtml(dirty)` and `const n = Number(dirty)`.
    if (ts.isVariableDeclaration(node) && node.initializer && ts.isIdentifier(node.name)) {
      const initializer = node.initializer;
      if (ts.isCallExpression(initializer)) {
        const name = calleeName(initializer);
        const tail = calleeTail(initializer);
        if (UNIVERSAL_SANITIZERS.has(name)) {
          scope.cleared.add(node.name.text);
          if (NUMERIC_COERCIONS.has(name)) scope.coerced.add(node.name.text);
          return;
        }
        if (HTML_ESCAPERS.has(name) || HTML_ESCAPERS.has(tail)) {
          scope.htmlSafe.add(node.name.text);
          return;
        }
        // `.replace(/[&<>"']/g, ...)` is hand-rolled HTML escaping.
        if (tail === "replace" || tail === "replaceAll") {
          const pattern = initializer.arguments[0];
          if (pattern && ts.isRegularExpressionLiteral(pattern) && /[&<>]/.test(pattern.text)) {
            scope.htmlSafe.add(node.name.text);
            return;
          }
        }
        // The same chain, one call away: `const safe = toSafeHtml(dirty)` where
        // `toSafeHtml` is declared in this file and escapes. See localHtmlEscapers.
        if (scope.htmlEscapers.has(name) || scope.htmlEscapers.has(tail)) scope.htmlSafe.add(node.name.text);
      }

      /*
       * `const sort = SORTABLE.has(requested) ? requested : "posted_on"`.
       *
       * An allowlist in a conditional expression, which the guard pass below could not
       * see: it looks for a membership test inside an `if` whose failing branch
       * terminates, and a ternary has no branch to terminate. The idiom is extremely
       * common for exactly the values that cannot be bound as parameters — a sort
       * column, an order direction, a table name — and it is arguably *safer* than the
       * `if`/`return` form, because there is no way to fall through it.
       *
       * The shape has to be exact to count: the tested value and the value taken on
       * success must be the same binding, and the fallback must be a constant. Anything
       * looser would clear a value that was merely mentioned near a membership test.
       */
      if (ts.isConditionalExpression(initializer)) {
        const cleared = allowlistedTernary(initializer);
        if (cleared) {
          scope.cleared.add(node.name.text);
          scope.allowlisted.add(node.name.text);
        }
      }

      /*
       * An allowlist written as a lookup table rather than as a test.
       *
       *     const DIMENSIONS: Record<string, string> = { day: "date(occurred_at)", … };
       *     const dimension = DIMENSIONS[c.req.query("dimension") ?? "day"];
       *
       * The caller chooses the **key**; the value is one of the literals in the
       * table. There is no key an attacker can send that makes this expression
       * evaluate to text they wrote, so the result is not their data — which is why
       * this is the standard way to build a dynamic `ORDER BY`, the one place a
       * parameter cannot go.
       *
       * No guard is required for that argument to hold. A missing key yields
       * `undefined`, which splices the word "undefined" into the statement — untidy,
       * and not injection. The table is what does the work, so the table is what is
       * checked: declared `const` in this file, initialised with an object literal,
       * every value a literal. A table assembled from request data clears nothing.
       */
      const bare = bareExpression(initializer);
      if (ts.isElementAccessExpression(bare) && indexesConstantTable(bare, file.source)) {
        scope.cleared.add(node.name.text);
        scope.allowlisted.add(node.name.text);
      }
      // `TABLE.get(key)`: the same table, addressed the only way a Map can be.
      if (ts.isCallExpression(bare) && readsConstantTable(bare, file.source)) {
        scope.cleared.add(node.name.text);
        scope.allowlisted.add(node.name.text);
      }
      /*
       * `const direction = params.dir === "asc" ? "asc" : "desc"`.
       *
       * Both branches are string literals, so the binding holds one of two constants
       * whatever the caller sent — the value has been *replaced* by a choice between
       * literals rather than filtered. This is the other half of how a dynamic ORDER BY
       * is written safely, and without it the column allowlist above was recognised while
       * the direction beside it was still read as the caller's.
       */
      if (ts.isConditionalExpression(bare) && isConstantString(bareExpression(bare.whenTrue)) && isConstantString(bareExpression(bare.whenFalse))) {
        scope.cleared.add(node.name.text);
        scope.allowlisted.add(node.name.text);
      }
    }

    if (!ts.isIfStatement(node)) return;

    // A guard only counts when its failing branch actually stops the handler.
    if (!branchTerminates(node.thenStatement) && !(node.elseStatement && branchTerminates(node.elseStatement))) return;

    const guarded = new Set<string>();
    /*
     * Record what this guard examined, and what that was derived from: `host` is tested,
     * and `host` was read off `target`, so `target` was examined too. Presence and type
     * checks do not count — `if (!id) return` says nothing about what `id` contains.
     */
    const markValidated = (name: string): void => {
      let current: string | null = name;
      for (let depth = 0; current && depth < 4; depth += 1) {
        scope.validated!.add(current);
        const initializer = scope.initializers.get(current);
        current = initializer ? rootIdentifier(initializer) : null;
      }
    };
    walk(node.expression, (inner) => {
      if (!ts.isCallExpression(inner)) return;
      // A schema this scan can read is applied field by field by `collectSchemaGuards`;
      // clearing the whole input here is the behaviour kept for one it cannot read.
      if (scope.schemaFacts && schemaCheck(inner, scope.schemaFacts.resolve)) return;
      const tail = calleeTail(inner);
      const name = calleeName(inner);
      // Whatever the content test is, the value was examined before the function went on.
      if (!PRESENCE_CHECKS.has(name)) {
        for (const argument of inner.arguments) {
          const tested = rootIdentifier(argument);
          if (tested) markValidated(tested);
        }
      }
      if (ts.isPropertyAccessExpression(inner.expression)) {
        const receiverRoot = rootIdentifier(inner.expression.expression);
        if (receiverRoot && /^(startsWith|endsWith|includes|match|test|search)$/.test(tail)) markValidated(receiverRoot);
      }

      // Allowlist membership: ALLOWED.has(x), list.includes(x), map[x] lookups.
      if (tail === "has" || tail === "includes" || tail === "hasOwnProperty") {
        for (const argument of inner.arguments) {
          const root = rootIdentifier(argument);
          if (root) guarded.add(root);
        }
      }
      /*
       * A fully anchored regular expression: `if (!/^\d{4}-\d{2}$/.test(period)) return`.
       *
       * This is one of the commonest ways a handler validates a path or an id, and
       * it was not modelled at all — which stayed invisible until `Bun.file` became
       * a filesystem sink and the traversal rule reported a handler whose parameter
       * had already been constrained to four digits, a dash and two digits.
       *
       * **Anchoring is required rather than inferred.** `/\d{4}/.test(x)` says only
       * that `x` contains four digits somewhere, so `../../etc/passwd1234` passes it;
       * a pattern anchored at both ends says what the value may be in its entirety.
       * A character class that can match a separator is rejected too, because
       * `/^[\w/.]+$/` is anchored and still admits traversal.
       */
      if (tail === "test") {
        const receiver = ts.isPropertyAccessExpression(inner.expression) ? inner.expression.expression : null;
        const pattern = receiver ? resolveExpression(receiver, scope) : null;
        if (pattern && ts.isRegularExpressionLiteral(pattern) && constrainsWholeValue(pattern.text)) {
          for (const argument of inner.arguments) {
            /*
             * A *path* constrains that path and nothing else. Taking the root
             * identifier instead — which the first version did — cleared the whole
             * object: `/^\/api\/orders\/\d+$/.test(url.pathname)` disarmed `url`,
             * and with it the `url.searchParams.get("name")` two handlers below,
             * which silently lost a path traversal the fixture has always caught.
             * The equality guard below already draws this distinction; this now
             * draws the same one.
             */
            if (ts.isIdentifier(argument)) {
              guarded.add(argument.text);
              continue;
            }
            const path = dottedPath(argument);
            if (path) scope.clearedPaths.add(path);
          }
        }
      }
      // Containment: resolved.startsWith(BASE) after path.resolve.
      if (tail === "startsWith") {
        const receiverRoot = ts.isPropertyAccessExpression(inner.expression)
          ? rootIdentifier(inner.expression.expression)
          : null;
        if (receiverRoot) scope.containmentChecked.add(receiverRoot);
      }
      /*
       * `if (!isContained(ROOT, absolute)) return notFound()` — the containment
       * test lives in a named predicate in the same file rather than inline.
       *
       * This is the shape the documentation everywhere recommends over prefix
       * matching, because `resolved.startsWith("/srv/previews")` also accepts
       * `/srv/previews-old`. Not recognising it means the engine reports the
       * better-written of two handlers and stays quiet about the worse one.
       *
       * Deliberately narrow: the predicate has to be declared in this file, its
       * body has to actually perform a containment test, and the failing branch
       * has to stop the handler — which the enclosing check above already
       * required.
       */
      if (predicateConfinesPaths(file, inner)) {
        for (const argument of inner.arguments) {
          const root = rootIdentifier(argument);
          if (root) scope.containmentChecked.add(root);
        }
      }
      if (name === "isAllowed" || name === "isPermitted" || tail === "validate" || tail === "parse" || tail === "safeParse") {
        for (const argument of inner.arguments) {
          const root = rootIdentifier(argument);
          if (root) guarded.add(root);
        }
      }
    });

    // Equality against a literal set also constrains the value.
    walk(node.expression, (inner) => {
      if (!ts.isBinaryExpression(inner)) return;
      const isEquality =
        inner.operatorToken.kind === ts.SyntaxKind.EqualsEqualsEqualsToken ||
        inner.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsEqualsToken;
      if (!isEquality) return;
      const constrain = (expression: ts.Node): void => {
        if (ts.isIdentifier(expression)) {
          guarded.add(expression.text);
          return;
        }
        const path = dottedPath(expression);
        // `request.method === "GET"` constrains the method and nothing else.
        if (path) scope.clearedPaths.add(path);
        // `target.protocol !== "https:"` examined a value this function derived — a parsed
        // URL, a decoded token — rather than a property of its own input object.
        const root = path ? path.split(".")[0]! : null;
        if (root && path!.includes(".") && scope.initializers.has(root)) markValidated(root);
      };
      if (isConstantString(inner.right)) constrain(inner.left);
      if (isConstantString(inner.left)) constrain(inner.right);
    });

    for (const name of guarded) {
      scope.allowlisted.add(name);
      scope.cleared.add(name);
    }
  });

  void file;
}

/** Calls that test whether a value is present or what type it is, not what it contains. */
const PRESENCE_CHECKS = new Set(["Array.isArray", "Boolean", "Object.keys", "Number.isNaN", "isNaN"]);

/** Does this branch stop the handler, so a failed guard cannot fall through? */
/**
 * Does this call invoke a local predicate whose body confines a path?
 *
 * Two shapes count, and only these two: resolving against a base and comparing
 * the result (`resolve` plus `startsWith`), and stepping from the base to the
 * candidate and refusing to climb (`relative` plus a `..` or `isAbsolute` test).
 * A helper that merely joins paths, or one this file does not declare, does not
 * count — an unread helper has to count against the guard rather than for it.
 */
function predicateConfinesPaths(file: ParsedFile, call: ts.CallExpression): boolean {
  if (!ts.isIdentifier(call.expression) || call.arguments.length < 2) return false;
  const name = call.expression.text;

  let declaration: ts.Node | undefined;
  walk(file.source, (node) => {
    if (declaration) return;
    if (ts.isFunctionDeclaration(node) && node.name?.text === name) declaration = node;
    if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      node.name.text === name &&
      node.initializer &&
      (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer))
    ) {
      declaration = node.initializer;
    }
  });
  if (!declaration) return false;

  let resolves = false;
  let steps = false;
  let comparesPrefix = false;
  let refusesClimb = false;
  walk(declaration, (node) => {
    if (ts.isCallExpression(node)) {
      const tail = calleeTail(node);
      if (tail === "resolve") resolves = true;
      if (tail === "relative") steps = true;
      if (tail === "isAbsolute") refusesClimb = true;
      if (tail === "startsWith") {
        const argument = node.arguments[0];
        if (argument && ts.isStringLiteralLike(argument) && argument.text.startsWith("..")) refusesClimb = true;
        else comparesPrefix = true;
      }
    }
    if (ts.isStringLiteralLike(node) && node.text.startsWith("..")) refusesClimb = true;
  });

  return (resolves && comparesPrefix) || (steps && refusesClimb);
}

function branchTerminates(statement: ts.Statement): boolean {
  let terminates = false;
  walk(statement, (node) => {
    if (ts.isReturnStatement(node) || ts.isThrowStatement(node) || isAbortCall(node)) terminates = true;
    // `res.status(403).json(...)` inside the guard is also a stop in practice,
    // but only when the handler returns immediately after; requiring an explicit
    // return keeps the check conservative in the safe direction. `ctx.throw(...)`
    // and `notFound()` are different: they abort by themselves.
  });
  return terminates;
}

/**
 * Is this call one the model already treats as producing a value the caller no longer
 * controls as text: a numeric or boolean coercion, an HTML escaper (named, or declared in
 * this file and recognised by its body), or a read from a constant lookup table?
 *
 * Exported for `engine/summaries.ts`, which has to tell "the model cleared this" apart
 * from "the model did not understand this" when it reads a function's returns.
 */
export function isSanitizingCall(call: ts.CallExpression, scope: TaintScope): boolean {
  const name = calleeName(call);
  const tail = calleeTail(call);
  if (UNIVERSAL_SANITIZERS.has(name)) return true;
  // `IdSchema.parse(raw)` where the schema constrains the whole value.
  if (isSchemaConstrained(call, scope)) return true;
  if (HTML_ESCAPERS.has(name) || HTML_ESCAPERS.has(tail)) return true;
  if (scope.htmlEscapers.has(name) || scope.htmlEscapers.has(tail)) return true;
  return readsConstantTable(call, call.getSourceFile());
}

/** `cond ? x : "fallback"` where `x` is tested for membership in the condition. */
export function isAllowlistedTernary(node: ts.ConditionalExpression): boolean {
  return allowlistedTernary(node);
}

export function isHtmlSafe(node: ts.Node, scope: TaintScope): boolean {
  if (ts.isIdentifier(node)) return scope.htmlSafe.has(node.text);
  if (ts.isCallExpression(node)) {
    const name = calleeName(node);
    const tail = calleeTail(node);
    if (HTML_ESCAPERS.has(name) || HTML_ESCAPERS.has(tail)) return true;
    if (tail === "replace" || tail === "replaceAll") {
      const pattern = node.arguments[0];
      if (pattern && ts.isRegularExpressionLiteral(pattern) && /[&<>]/.test(pattern.text)) return true;
    }
    // A local helper whose body escapes, whatever a project chose to call it.
    if (scope.htmlEscapers.has(name) || scope.htmlEscapers.has(tail)) return true;
  }
  const root = rootIdentifier(node);
  return root ? scope.htmlSafe.has(root) : false;
}

export function rootOf(node: ts.Node): string | null {
  return rootIdentifier(node);
}

/** Every function-like node in a file, so rules can scope taint per handler. */
export function functionsIn(source: ts.SourceFile): ts.Node[] {
  const out: ts.Node[] = [];
  walk(source, (node) => {
    if (
      ts.isFunctionDeclaration(node) ||
      ts.isFunctionExpression(node) ||
      ts.isArrowFunction(node) ||
      ts.isMethodDeclaration(node)
    ) {
      out.push(node);
    }
  });
  // The module body itself can contain top-level sinks.
  out.push(source);
  return out;
}

/**
 * Is this dotted path a read of something the server attached to the request?
 *
 * The test is deliberately shallow: exactly the one property after the root.
 * `request.user.accountId` is the authenticated subject and is not the caller's;
 * `request.body.user` is a field the caller chose to send under a name that
 * happens to collide with ours, and it is entirely theirs. An earlier version
 * checked every segment, which silently disarmed taint for any request field
 * named `state`, `account`, `auth`, `tenant`, `workspace`, `identity`, or
 * `subject` — common enough that the loss was invisible and large.
 */
/**
 * Is any segment of this path something a framework or middleware attached?
 *
 * This inspected `segments[1]` only — the property read directly off the request
 * object — and the reasoning was sound for Express, where `req.user` is the
 * authenticated subject and `req.body.user` is a field the caller named. It is wrong
 * for every framework that puts its own state one level deeper. h3 and Nitro use
 * `event.context`:
 *
 *     event.context.session.tenantId    // the authenticated tenant
 *     event.context.auth.userId         // the authenticated subject
 *
 * Segment 1 is `context`, which is not on the list, so both read as caller data — and
 * a rule that treats the authenticated tenant as attacker input reports the correctly
 * scoped query and misses the unscoped one.
 *
 * The `req.body.user` case is still handled, because `body` is a request property and
 * a caller's own field never appears under a *container* segment: what makes
 * `event.context` different from `req.body` is that the framework owns it. So the
 * container segments are named, and a server-attached property is looked for anywhere
 * a container has put it.
 */
const SERVER_CONTAINER_SEGMENTS = new Set(["context", "ctx", "locals", "state", "vars", "var", "env", "scope"]);

function isServerAttached(path: string): boolean {
  const segments = path.split(".");
  if (segments.length < 2) return false;
  if (SERVER_ATTACHED_PROPERTIES.has(segments[1]!)) return true;
  // `event.context.session.…` — one container hop, then the attached property.
  for (let index = 1; index < segments.length - 1; index += 1) {
    if (!SERVER_CONTAINER_SEGMENTS.has(segments[index]!)) continue;
    if (SERVER_ATTACHED_PROPERTIES.has(segments[index + 1]!)) return true;
  }
  return false;
}

/** `request.body.total` as a string, or null when the base is not an identifier. */
function dottedPath(expression: ts.Node): string | null {
  if (ts.isIdentifier(expression)) return expression.text;
  if (ts.isPropertyAccessExpression(expression)) {
    const base = dottedPath(expression.expression);
    return base ? `${base}.${expression.name.text}` : null;
  }
  return null;
}

/**
 * Taint for rules about *what the value is* rather than *what text it carries*.
 *
 * `Number(req.body.quantity)` cannot inject a quote, so the injection rules are
 * right to stop there. It is still entirely the caller's number, so a rule about
 * a price or a limit must keep following it — otherwise every business-logic
 * defect disappears behind a coercion that looks like a fix.
 */
export function valueTaintOrigin(node: ts.Node, scope: TaintScope, requestParams?: Set<string>): string | null {
  // `z.number()` stops a quote, not an amount: the number is still the caller's.
  if (!ts.isIdentifier(node) && scope.schemaFacts && constrainedValue(schemaViewOf(node, scope.schemaFacts))?.numeric) {
    return withoutSchemas(scope, () => taintOrigin(node, scope, requestParams));
  }
  if (ts.isCallExpression(node) && NUMERIC_COERCIONS.has(calleeName(node))) {
    for (const argument of node.arguments) {
      const origin = valueTaintOrigin(argument, scope, requestParams);
      if (origin) return origin;
    }
    return null;
  }
  if (ts.isIdentifier(node) && scope.coerced.has(node.text)) {
    const root = scope.roots.get(node.text);
    if (root) return root.origin;
    // The binding was cleared by the coercion before a root was recorded, so
    // recover the origin from the expression it was coerced from.
    const declared = coercedFrom(scope, node.text);
    if (declared) return valueTaintOrigin(declared, scope, requestParams);
  }
  if (ts.isBinaryExpression(node) || ts.isTemplateExpression(node)) {
    for (const part of dynamicParts(node)) {
      const origin = valueTaintOrigin(part, scope, requestParams);
      if (origin) return origin;
    }
  }
  return taintOrigin(node, scope, requestParams);
}

/** The expression a numerically-coerced binding was built from. */
function coercedFrom(scope: TaintScope, name: string): ts.Expression | null {
  const body = (scope.fn as ts.FunctionLikeDeclaration).body;
  if (!body) return null;
  let found: ts.Expression | null = null;
  walk(body, (node) => {
    if (found) return;
    if (!ts.isVariableDeclaration(node) || !ts.isIdentifier(node.name) || node.name.text !== name) return;
    if (!node.initializer || !ts.isCallExpression(node.initializer)) return;
    if (!NUMERIC_COERCIONS.has(calleeName(node.initializer))) return;
    found = node.initializer.arguments[0] ?? null;
  });
  return found;
}

/* ------------------------------------------------------------- schema validation */

/**
 * Could anything in this file validate against a schema? A textual gate, so a file that
 * calls no parse- or validate-shaped method pays nothing for the schema reader. `JSON.parse`
 * and the other well-known parsers are not schema calls.
 */
const SCHEMA_CALL_TEXT =
  /\.(safeParse|safeParseAsync|parseAsync|validate|validateSync|validateAsync|isValid|isValidSync|attempt)\s*\(|(?<!\b(JSON|Date|url|path|qs|querystring|cookie|URL))\.parse\s*\(/;
const SCHEMA_GATE = new WeakMap<ParsedFile, boolean>();

function mayValidateWithSchema(file: ParsedFile): boolean {
  let gate = SCHEMA_GATE.get(file);
  if (gate === undefined) {
    gate = SCHEMA_CALL_TEXT.test(file.text);
    SCHEMA_GATE.set(file, gate);
  }
  return gate;
}

/** Does a schema constrain this value to something that cannot carry caller text? */
export function isSchemaConstrained(node: ts.Node, scope: TaintScope): boolean {
  const facts = scope.schemaFacts;
  if (!facts || ts.isIdentifier(node)) return false;
  if (facts.views.size === 0 && facts.guards.size === 0) {
    // Without a binding or a guard, only a chain that starts at a parse call can be one.
    let base: ts.Node = node;
    for (let depth = 0; depth < 12; depth += 1) {
      if (ts.isPropertyAccessExpression(base) || ts.isElementAccessExpression(base) || ts.isParenthesizedExpression(base) || ts.isAwaitExpression(base) || ts.isNonNullExpression(base) || ts.isAsExpression(base)) {
        base = base.expression;
        continue;
      }
      break;
    }
    if (!ts.isCallExpression(base)) return false;
  }
  return constrainedValue(schemaViewOf(node, facts)) !== null;
}

/** Run `read` as the model would without any schema knowledge: the raw origin of a value. */
function withoutSchemas<T>(scope: TaintScope, read: () => T): T {
  const facts = scope.schemaFacts;
  scope.schemaFacts = undefined;
  try {
    return read();
  } finally {
    scope.schemaFacts = facts;
  }
}

/** A binding whose value the schema constrains: not caller text; a number keeps its value taint. */
function bindConstrained(name: string, numeric: boolean, source: ts.Expression, declaration: ts.Node, scope: TaintScope, requestParams: Set<string>): void {
  scope.cleared.add(name);
  scope.allowlisted.add(name);
  if (!numeric) return;
  const origin = withoutSchemas(scope, () => taintOrigin(source, scope, requestParams));
  if (!origin) return;
  scope.roots.set(name, { name, origin, declaration });
  scope.coerced.add(name);
}

/**
 * `const data = Body.parse(req.body)`, `const parsed = Body.safeParse(req.body)`,
 * `const body = parsed.data`. Records the view so later reads go field by field; a value the
 * schema constrains as a whole is cleared here. True when the binding was fully handled.
 */
function bindSchemaValue(name: string, initializer: ts.Expression, declaration: ts.Node, scope: TaintScope, requestParams: Set<string>): boolean {
  const facts = scope.schemaFacts;
  if (!facts) return false;
  const view = schemaViewOf(initializer, facts);
  if (!view) return false;
  const constrained = constrainedValue(view);
  if (constrained) {
    bindConstrained(name, constrained.numeric, initializer, declaration, scope, requestParams);
    return true;
  }
  facts.views.set(name, view);
  return false;
}

/** `const { id, name } = Body.parse(req.body)`: each field by what the schema says of it. */
function bindSchemaFields(declaration: ts.VariableDeclaration, pattern: ts.ObjectBindingPattern, scope: TaintScope, requestParams: Set<string>): boolean {
  const facts = scope.schemaFacts;
  const initializer = declaration.initializer;
  if (!facts || !initializer) return false;
  const view = schemaViewOf(initializer, facts);
  if (!view) return false;
  const origin = withoutSchemas(scope, () => taintOrigin(initializer, scope, requestParams));
  for (const element of pattern.elements) {
    if (element.dotDotDotToken) {
      if (origin) for (const bound of boundNames(element.name)) scope.roots.set(bound, { name: bound, origin, declaration });
      continue;
    }
    const key = element.propertyName && (ts.isIdentifier(element.propertyName) || ts.isStringLiteral(element.propertyName))
      ? element.propertyName.text
      : ts.isIdentifier(element.name)
        ? element.name.text
        : null;
    const fieldView = key ? stepView(view, key) : null;
    const constrained = constrainedValue(fieldView);
    if (constrained && ts.isIdentifier(element.name)) {
      bindConstrained(element.name.text, constrained.numeric, initializer, declaration, scope, requestParams);
      continue;
    }
    if (!origin) continue;
    for (const bound of boundNames(element.name)) scope.roots.set(bound, { name: bound, origin, declaration });
    if (fieldView && ts.isIdentifier(element.name)) facts.views.set(element.name.text, fieldView);
  }
  return true;
}

/**
 * Inputs this function validated in place before going on:
 *
 *     if (!Body.safeParse(req.body).success) return res.status(400).end();
 *     const check = Body.safeParse(req.body); if (!check.success) return …;
 *     const { error } = Body.validate(req.body); if (error) return …;
 *     if (!(await Body.isValid(req.body))) throw …;
 *     Body.parse(req.body);                      // throws on failure
 *
 * Recorded by the input's dotted path with the schema's shape, so `req.body.id` reads as
 * constrained when `id` is and `req.body.name` stays the caller's when it is open. A whole
 * identifier the schema constrains is cleared outright, as an allowlist guard would.
 */
function collectSchemaGuards(body: ts.Node, scope: TaintScope): void {
  const facts = scope.schemaFacts!;
  const declared = new Map<string, ts.Expression>();
  const record = (input: ts.Expression, shape: SchemaShape): void => {
    let bare: ts.Node = input;
    while (ts.isParenthesizedExpression(bare) || ts.isAwaitExpression(bare) || ts.isAsExpression(bare) || ts.isNonNullExpression(bare)) bare = bare.expression;
    const path = schemaPath(bare);
    if (!path) return;
    facts.guards.set(path, shape);
    if (ts.isIdentifier(bare) && shape.kind === "constrained") {
      scope.cleared.add(bare.text);
      scope.allowlisted.add(bare.text);
      if (shape.numeric) scope.coerced.add(bare.text);
    }
  };
  walk(body, (node) => {
    if (!ts.isVariableDeclaration(node) || !node.initializer) return;
    if (ts.isIdentifier(node.name)) declared.set(node.name.text, node.initializer);
    else for (const bound of boundNames(node.name)) declared.set(bound, node.initializer);
    // `const data = Body.parse(req.body)` throws on failure, so `req.body` was validated too.
    const parsed = schemaParse(node.initializer, facts.resolve);
    if (parsed && parsed.path === "" && failureStops(node, body)) record(parsed.input, parsed.shape);
  });
  walk(body, (node) => {
    if (ts.isExpressionStatement(node)) {
      const parsed = schemaParse(node.expression, facts.resolve);
      if (parsed && parsed.path === "" && failureStops(node, body)) record(parsed.input, parsed.shape);
      return;
    }
    if (!ts.isIfStatement(node)) return;
    if (!branchTerminates(node.thenStatement) && !(node.elseStatement && branchTerminates(node.elseStatement))) return;
    walk(node.expression, (inner) => {
      if (ts.isCallExpression(inner)) {
        const checked = schemaCheck(inner, facts.resolve);
        if (checked) record(checked.input, checked.shape);
        return;
      }
      if (!ts.isIdentifier(inner)) return;
      const parent = inner.parent;
      if (parent && ts.isPropertyAccessExpression(parent) && parent.name === inner) return;
      const initializer = declared.get(inner.text);
      const parsed = initializer ? schemaParse(initializer, facts.resolve) : null;
      if (parsed && parsed.path !== "") record(parsed.input, parsed.shape);
    });
  });
}

function schemaPath(node: ts.Node): string | null {
  if (ts.isIdentifier(node)) return node.text;
  if (ts.isPropertyAccessExpression(node)) {
    const base = schemaPath(node.expression);
    return base ? `${base}.${node.name.text}` : null;
  }
  return null;
}

/**
 * Does a throw at `node` stop this function? Not when it happens inside a nested function,
 * which runs some other time, nor inside a `try` whose `catch` carries on.
 */
function failureStops(node: ts.Node, body: ts.Node): boolean {
  let child: ts.Node = node;
  for (let current = node.parent; current && current !== body; current = current.parent) {
    if (ts.isFunctionLike(current)) return false;
    if (ts.isTryStatement(current) && current.tryBlock === child && current.catchClause && !branchTerminates(current.catchClause.block)) return false;
    child = current;
  }
  return true;
}
