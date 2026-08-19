import ts from "typescript";
import type { ParsedFile } from "./parse.js";
import { calleeName, calleeTail, dynamicParts, expressionName, isConstantString, walk } from "./helpers.js";

/**
 * Intra-procedural taint tracking.
 *
 * The scope is deliberately honest: taint is followed inside a single function
 * body, through local bindings, template literals, string concatenation, and a
 * short list of pass-through calls. It does not follow values across module
 * boundaries or into callees. Everything it cannot follow is reported as a
 * coverage limitation rather than guessed at, because a scanner that quietly
 * over-reaches produces exactly the false positives this engine exists to avoid.
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

/** Property paths on a request object that a caller controls. */
const REQUEST_PROPERTIES = new Set(["query", "body", "params", "headers", "cookies", "url", "search", "form"]);

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
  if (ts.isNonNullExpression(expression) || ts.isParenthesizedExpression(expression)) {
    return rootIdentifier(expression.expression);
  }
  return null;
}

/** Is this expression a direct read of caller-controlled data? */
function directTaintOrigin(node: ts.Node, requestParams: Set<string>): string | null {
  if (ts.isPropertyAccessExpression(node)) {
    const root = rootIdentifier(node);
    const name = expressionName(node);
    if (root && requestParams.has(root)) {
      const property = node.name.text;
      // Anything reached through a server-attached property is the application's own
      // data, however deep the access goes.
      for (const segment of name.split(".").slice(1)) {
        if (SERVER_ATTACHED_PROPERTIES.has(segment)) return null;
      }
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

  if (ts.isAwaitExpression(node)) return directTaintOrigin(node.expression, requestParams);
  if (ts.isParenthesizedExpression(node)) return directTaintOrigin(node.expression, requestParams);
  if (ts.isAsExpression(node) || ts.isSatisfiesExpression(node) || ts.isNonNullExpression(node)) {
    return directTaintOrigin(node.expression, requestParams);
  }
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
export function analyzeFunction(file: ParsedFile, fn: ts.Node): TaintScope {
  const requestParams = requestParameters(fn);
  const scope: TaintScope = {
    fn,
    roots: new Map(),
    cleared: new Set(),
    htmlSafe: new Set(),
    allowlisted: new Set(),
    containmentChecked: new Set(),
    coerced: new Set(),
    clearedPaths: new Set(),
    taintedCollections: new Map(),
    initializers: new Map()
  };

  // A request parameter is itself a tainted root, so `req.query.q` used inline
  // (without a local binding) is still recognised.
  for (const name of requestParams) {
    scope.roots.set(name, { name, origin: `${name} (inbound request)`, declaration: fn });
  }

  const body = (fn as ts.FunctionLikeDeclaration).body;
  if (!body) return scope;

  // Two passes: bind taint first, then apply guards, so a guard written after
  // the declaration still clears the binding.
  walk(body, (node) => {
    if (ts.isVariableDeclaration(node) && node.initializer && ts.isIdentifier(node.name)) {
      scope.initializers.set(node.name.text, node.initializer);
      const origin = taintOrigin(node.initializer, scope, requestParams);
      if (origin) scope.roots.set(node.name.text, { name: node.name.text, origin, declaration: node });
      return;
    }

    // `const { status, customer } = req.query` is how most handlers actually read
    // their input. Without this every one of those flows stops at the declaration,
    // which is the difference between finding a query built from user data and
    // finding nothing at all.
    if (ts.isVariableDeclaration(node) && node.initializer && ts.isObjectBindingPattern(node.name)) {
      const origin = taintOrigin(node.initializer, scope, requestParams);
      if (!origin) return;
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

  collectAccumulators(body, scope, requestParams);
  applyGuards(file, body, scope);
  return scope;
}

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
    const initializer = scope.initializers.get(current.text);
    if (!initializer) return current;
    current = initializer;
  }
  return current;
}

/** Why this expression is tainted, or null when it is not. */
export function taintOrigin(node: ts.Node, scope: TaintScope, requestParams?: Set<string>): string | null {
  const params = requestParams ?? new Set<string>();

  const direct = directTaintOrigin(node, params);
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
    const root = rootIdentifier(node);
    if (root && !scope.cleared.has(root) && scope.roots.has(root)) return scope.roots.get(root)!.origin;
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
      const collection = rootIdentifier(node.expression.expression);
      if (collection) {
        const accumulated = scope.taintedCollections.get(collection);
        if (accumulated) return accumulated;
      }
    }
    if (UNIVERSAL_SANITIZERS.has(name)) return null;
    if (HTML_ESCAPERS.has(name) || HTML_ESCAPERS.has(tail)) return null;
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
    for (const argument of node.arguments) {
      const origin = taintOrigin(argument, scope, params);
      if (origin) return `${origin} via ${name || tail}()`;
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
    return taintOrigin(node.expression, scope, params);
  }

  if (ts.isConditionalExpression(node)) {
    return taintOrigin(node.whenTrue, scope, params) ?? taintOrigin(node.whenFalse, scope, params);
  }

  return null;
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
          }
        }
      }
    }

    if (!ts.isIfStatement(node)) return;

    // A guard only counts when its failing branch actually stops the handler.
    if (!branchTerminates(node.thenStatement) && !(node.elseStatement && branchTerminates(node.elseStatement))) return;

    const guarded = new Set<string>();
    walk(node.expression, (inner) => {
      if (!ts.isCallExpression(inner)) return;
      const tail = calleeTail(inner);
      const name = calleeName(inner);

      // Allowlist membership: ALLOWED.has(x), list.includes(x), map[x] lookups.
      if (tail === "has" || tail === "includes" || tail === "hasOwnProperty") {
        for (const argument of inner.arguments) {
          const root = rootIdentifier(argument);
          if (root) guarded.add(root);
        }
      }
      // Containment: resolved.startsWith(BASE) after path.resolve.
      if (tail === "startsWith") {
        const receiverRoot = ts.isPropertyAccessExpression(inner.expression)
          ? rootIdentifier(inner.expression.expression)
          : null;
        if (receiverRoot) scope.containmentChecked.add(receiverRoot);
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

/** Does this branch stop the handler, so a failed guard cannot fall through? */
function branchTerminates(statement: ts.Statement): boolean {
  let terminates = false;
  walk(statement, (node) => {
    if (ts.isReturnStatement(node) || ts.isThrowStatement(node)) terminates = true;
    // `res.status(403).json(...)` inside the guard is also a stop in practice,
    // but only when the handler returns immediately after; requiring an explicit
    // return keeps the check conservative in the safe direction.
  });
  return terminates;
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
