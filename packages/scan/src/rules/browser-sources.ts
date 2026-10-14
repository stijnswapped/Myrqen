import ts from "typescript";
import { calleeName, calleeTail, dynamicParts, enclosingFunction, expressionName, walk } from "../ast/helpers.js";
import { HTML_ESCAPERS, htmlEscapersIn } from "../ast/taint.js";
import type { ParsedFile } from "../ast/parse.js";

/**
 * Values a *browser* hands to page script, and nothing else.
 *
 * The taint model in `ast/taint.ts` starts from an entry point: a request a server
 * receives. Code that runs in the page has no request. Its caller-controlled input
 * is the address bar, the referring page, the window's name, and whatever another
 * window posts to it — and none of those is a parameter of any function, so the
 * request model is structurally unable to see them. That is the whole reason this
 * module exists, and why it is separate rather than a seed: a seed is "this
 * parameter is the caller's", and `location.hash` is not a parameter.
 *
 * The spec is deliberately thin — a source list, a pass-through list, and a guard
 * test — so that when the engine grows cross-function flow the same three lists can
 * be handed to it unchanged.
 *
 * What it does not do, stated so a reader can trust a silence correctly:
 *
 *  - A value that leaves the function it was read in through a call is lost. An
 *    unknown function is assumed to transform its argument, which is the opposite
 *    default to the server-side model and is chosen on purpose: page code routes
 *    almost everything through framework helpers, and assuming taint survives them
 *    would report every templating library in the bundle.
 *  - The one exception is a function declared in the same file that *reads* a source
 *    and returns it — `function inviterFromLink() { return decodeURIComponent(location.hash.slice(1)) }`.
 *    What it returns is judged by the same lists, inside the helper, so a helper that
 *    escapes or validates before returning stays clean. Arguments are still not
 *    followed into it.
 *  - A closure reading a binding from an enclosing function *is* followed, because
 *    an event handler defined beside the `const` it reads is the ordinary shape.
 */

/**
 * The whole current address. Caller-controlled — a link chooses it — but it is, by
 * construction, an address on this origin, so a rule about leaving the origin must
 * not treat it as a destination the caller picked. A part read out of it (its query,
 * its fragment) is described separately, below, and is the caller's choice outright.
 */
export const FULL_ADDRESS = "the full page address";

/** Dotted reads that are the address, the referrer, or the window's name. */
const SOURCE_READS: ReadonlyArray<{ pattern: RegExp; describes: string }> = Object.freeze([
  {
    pattern: /^(?:window\.|self\.|globalThis\.|document\.|top\.|parent\.)?location\.(?:hash|search)$/,
    describes: "the page's query string or fragment"
  },
  {
    pattern: /^(?:window\.|self\.|globalThis\.|document\.|top\.|parent\.)?location\.href$/,
    describes: FULL_ADDRESS
  },
  { pattern: /^(?:window\.)?document\.(?:URL|documentURI)$/, describes: FULL_ADDRESS },
  { pattern: /^(?:window\.)?document\.referrer$/, describes: "the referring page (document.referrer)" },
  { pattern: /^(?:window|self|globalThis)\.name$/, describes: "the window name (window.name)" }
]);

/**
 * Hooks that return the current route's query or parameters.
 *
 * `useSearchParams` is both Next's and React Router's (the latter returns a tuple);
 * `useParams` and `useLocation` return values taken from the URL in every router
 * that has them.
 */
const ROUTE_HOOKS = new Set(["useSearchParams", "useParams", "useLocation"]);

/** Hooks whose `query` property is the route's query string. */
const ROUTER_HOOKS = new Set(["useRouter", "useRoute"]);

/** String operations that hand their input back, possibly rearranged. */
const PASS_THROUGH = new Set([
  "decodeURIComponent",
  "decodeURI",
  "unescape",
  "atob",
  "String",
  "JSON.parse",
  "trim",
  "trimStart",
  "trimEnd",
  "slice",
  "substring",
  "substr",
  "split",
  "join",
  "toString",
  "toLowerCase",
  "toUpperCase",
  "concat",
  "at",
  "get",
  "getAll",
  "pop",
  "shift",
  "padStart",
  "padEnd",
  "normalize"
]);

/** Calls that turn a value into something that cannot carry markup or a scheme. */
const NEUTRALISERS = new Set(["Number", "parseInt", "parseFloat", "Boolean", "BigInt", "encodeURIComponent", "encodeURI"]);

export interface BrowserTaint {
  /** Why this expression carries browser-supplied input, or null. */
  originOf(node: ts.Node): string | null;
}

const CACHE = new WeakMap<ParsedFile, BrowserTaint>();

/** Memoised per file: three rules ask the same question of the same tree. */
export function browserTaint(file: ParsedFile): BrowserTaint {
  const cached = CACHE.get(file);
  if (cached) return cached;
  const built = build(file);
  CACHE.set(file, built);
  return built;
}

function build(file: ParsedFile): BrowserTaint {
  const escapers = htmlEscapersIn(file);
  const declarationOrigins = new Map<ts.Node, string | null>();

  const isEscaper = (call: ts.CallExpression): boolean => {
    const name = calleeName(call);
    const tail = calleeTail(call);
    if (HTML_ESCAPERS.has(name) || HTML_ESCAPERS.has(tail) || escapers.has(name) || escapers.has(tail)) return true;
    if (NEUTRALISERS.has(name)) return true;
    if (tail === "replace" || tail === "replaceAll") {
      const pattern = call.arguments[0];
      if (pattern && ts.isRegularExpressionLiteral(pattern) && /[<>&]/.test(pattern.text)) return true;
    }
    return false;
  };

  const originOf = (node: ts.Node, depth = 0): string | null => {
    if (depth > 12) return null;
    const next = (inner: ts.Node): string | null => originOf(inner, depth + 1);

    if (
      ts.isParenthesizedExpression(node) ||
      ts.isAwaitExpression(node) ||
      ts.isNonNullExpression(node) ||
      ts.isAsExpression(node) ||
      ts.isSatisfiesExpression(node) ||
      ts.isTypeAssertionExpression(node)
    ) {
      return next(node.expression);
    }

    if (ts.isPropertyAccessExpression(node)) {
      const name = expressionName(node);
      for (const source of SOURCE_READS) if (source.pattern.test(name)) return `${name} (${source.describes})`;
      if (node.name.text === "data" && isUnguardedMessageEvent(node.expression)) {
        return `${name} (a message posted by any window, with no origin check)`;
      }
      if (node.name.text === "query" && isRouterObject(node.expression, depth)) {
        return `${name} (the route's query string)`;
      }
      const base = next(node.expression);
      // `new URL(location.href).searchParams` is the query, not the whole address.
      if (base && ["searchParams", "search", "hash"].includes(node.name.text) && base.includes(FULL_ADDRESS)) {
        return `${name} (the page's query string or fragment)`;
      }
      return base;
    }

    if (ts.isElementAccessExpression(node)) return next(node.expression);

    if (ts.isIdentifier(node)) {
      const declaration = declarationFor(node);
      if (!declaration) return null;
      if (declarationOrigins.has(declaration)) return declarationOrigins.get(declaration) ?? null;
      declarationOrigins.set(declaration, null); // cycle guard
      const origin = declarationOrigin(declaration, node, depth);
      declarationOrigins.set(declaration, origin);
      return origin;
    }

    if (ts.isTemplateExpression(node) || ts.isBinaryExpression(node)) {
      if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) return next(node.right);
      for (const part of dynamicParts(node)) {
        const origin = next(part);
        if (origin) return origin;
      }
      return null;
    }

    if (ts.isConditionalExpression(node)) return next(node.whenTrue) ?? next(node.whenFalse);

    if (ts.isNewExpression(node)) {
      const constructed = expressionName(node.expression);
      if (constructed === "URLSearchParams" || constructed === "URL") {
        const first = node.arguments?.[0];
        return first ? next(first) : null;
      }
      return null;
    }

    if (ts.isCallExpression(node)) {
      if (isEscaper(node)) return null;
      const name = calleeName(node);
      const tail = calleeTail(node);
      if (ts.isIdentifier(node.expression) && ROUTE_HOOKS.has(node.expression.text)) {
        return `${node.expression.text}() (the route's address)`;
      }
      if (ts.isIdentifier(node.expression)) {
        const helper = localFunction(node.expression);
        if (helper) {
          const origin = returnedOrigin(helper, depth);
          if (origin) return origin;
        }
      }
      // A substitution keeps the rest of the string — `.replace(/\+/g, " ")` — unless it
      // deletes everything outside a character class, which is an allowlist.
      if ((tail === "replace" || tail === "replaceAll") && ts.isPropertyAccessExpression(node.expression)) {
        const pattern = node.arguments[0];
        const allowlist = pattern && ts.isRegularExpressionLiteral(pattern) && /\[\^/.test(pattern.text);
        return allowlist ? null : next(node.expression.expression);
      }
      if (!PASS_THROUGH.has(name) && !PASS_THROUGH.has(tail)) return null;
      if (ts.isPropertyAccessExpression(node.expression)) {
        const origin = next(node.expression.expression);
        if (origin) return origin;
      }
      for (const argument of node.arguments) {
        const origin = next(argument);
        if (origin) return origin;
      }
      return null;
    }

    return null;
  };

  /** What a same-file helper returns, judged inside the helper. Memoised, cycle-safe. */
  const returnOrigins = new Map<ts.Node, string | null>();
  const returnedOrigin = (helper: ts.FunctionLikeDeclaration, depth: number): string | null => {
    if (returnOrigins.has(helper)) return returnOrigins.get(helper) ?? null;
    returnOrigins.set(helper, null);
    let origin: string | null = null;
    const body = helper.body;
    if (body && !ts.isBlock(body)) {
      origin = originOf(body, depth + 1);
    } else if (body) {
      walk(body, (inner) => {
        if (origin) return;
        if (ts.isReturnStatement(inner) && inner.expression && enclosingFunction(inner) === helper) {
          origin = originOf(inner.expression, depth + 1);
        }
      });
    }
    returnOrigins.set(helper, origin);
    return origin;
  };

  /**
   * A `router` or `route` object whose `query` is the address.
   *
   * Only an object that is visibly a router counts: the result of `useRouter()` /
   * `useRoute()`, or Vue's `this.$route`. A local called `router` that this file
   * built itself is not the URL.
   */
  const isRouterObject = (node: ts.Node, depth: number): boolean => {
    if (ts.isPropertyAccessExpression(node) && node.name.text === "$route") return true;
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && ROUTER_HOOKS.has(node.expression.text)) return true;
    if (ts.isIdentifier(node) && depth < 12) {
      const declaration = declarationFor(node);
      if (declaration && ts.isVariableDeclaration(declaration) && declaration.initializer) {
        const init = unwrap(declaration.initializer);
        return ts.isCallExpression(init) && ts.isIdentifier(init.expression) && ROUTER_HOOKS.has(init.expression.text);
      }
    }
    return false;
  };

  const declarationOrigin = (declaration: ts.Node, use: ts.Identifier, depth: number): string | null => {
    if (ts.isVariableDeclaration(declaration)) {
      if (!declaration.initializer) return assignedOrigin(declaration, use, depth);
      // `const [params] = useSearchParams()` and `const { q } = router.query`.
      const origin = originOf(declaration.initializer, depth + 1) ?? assignedOrigin(declaration, use, depth);
      if (!origin) return null;
      if (clearedByGuard(declaration, use)) return null;
      return origin;
    }
    if (ts.isBindingElement(declaration)) {
      let container: ts.Node = declaration.parent;
      while (container && !ts.isVariableDeclaration(container) && !ts.isParameter(container)) container = container.parent;
      if (container && ts.isVariableDeclaration(container) && container.initializer) {
        const origin = originOf(container.initializer, depth + 1);
        if (!origin || clearedByGuard(container, use)) return null;
        return origin;
      }
      if (container && ts.isParameter(container)) return parameterOrigin(container, declaration);
      return null;
    }
    if (ts.isParameter(declaration)) return parameterOrigin(declaration, null);
    return null;
  };

  /** `let target; target = location.hash.slice(1)` — a later assignment taints the binding. */
  const assignedOrigin = (declaration: ts.VariableDeclaration, use: ts.Identifier, depth: number): string | null => {
    if (!ts.isIdentifier(declaration.name)) return null;
    const name = declaration.name.text;
    const scopeNode = enclosingFunction(declaration) ?? declaration.getSourceFile();
    let found: string | null = null;
    walk(scopeNode, (inner) => {
      if (found) return;
      if (!ts.isBinaryExpression(inner) || inner.operatorToken.kind !== ts.SyntaxKind.EqualsToken) return;
      if (!ts.isIdentifier(inner.left) || inner.left.text !== name) return;
      if (inner.getStart() > use.getStart()) return;
      found = originOf(inner.right, depth + 1);
    });
    return found;
  };

  /**
   * A destructured parameter of a page component: `({ searchParams })` in a Next
   * page receives the query string. Only that name, and only on a default-exported
   * page module, because a parameter is otherwise somebody else's value.
   */
  const parameterOrigin = (parameter: ts.ParameterDeclaration, element: ts.BindingElement | null): string | null => {
    if (!element) return null;
    const property = element.propertyName && ts.isIdentifier(element.propertyName)
      ? element.propertyName.text
      : ts.isIdentifier(element.name) ? element.name.text : null;
    if (property !== "searchParams") return null;
    if (!/(?:^|\/)page\.[cm]?[jt]sx?$/.test(file.relativePath)) return null;
    void parameter;
    return "searchParams (the page's query string)";
  };

  return { originOf: (node) => originOf(node) };
}

/** `function f() {}` or `const f = () => …` declared in this file, by the name it is called with. */
function localFunction(callee: ts.Identifier): ts.FunctionLikeDeclaration | null {
  const declaration = declarationFor(callee);
  if (!declaration) return null;
  if (ts.isFunctionDeclaration(declaration)) return declaration;
  if (ts.isVariableDeclaration(declaration) && declaration.initializer) {
    const init = unwrap(declaration.initializer);
    if (ts.isArrowFunction(init) || ts.isFunctionExpression(init)) return init;
  }
  return null;
}

function unwrap(node: ts.Expression): ts.Expression {
  let current = node;
  while (ts.isAwaitExpression(current) || ts.isParenthesizedExpression(current) || ts.isAsExpression(current) || ts.isNonNullExpression(current)) {
    current = current.expression;
  }
  return current;
}

/**
 * The declaration a name refers to at this point, found by walking outward through
 * the enclosing functions and blocks. No type checker is available to the engine,
 * so this is the lexical rule and nothing cleverer: the nearest enclosing scope that
 * declares the name wins, which is exactly what JavaScript does.
 */
export function declarationFor(use: ts.Identifier): ts.Node | undefined {
  const name = use.text;
  let scope: ts.Node | undefined = use.parent;
  while (scope) {
    if (ts.isBlock(scope) || ts.isSourceFile(scope) || ts.isFunctionLike(scope) || ts.isCaseBlock(scope) || ts.isForStatement(scope) || ts.isForOfStatement(scope) || ts.isForInStatement(scope)) {
      const found = declaredDirectlyIn(scope, name);
      if (found) return found;
    }
    scope = scope.parent;
  }
  return undefined;
}

function declaredDirectlyIn(scope: ts.Node, name: string): ts.Node | undefined {
  if (ts.isFunctionLike(scope)) {
    for (const parameter of scope.parameters) {
      const found = bindingNamed(parameter.name, name);
      if (found) return found === parameter.name ? parameter : found;
    }
    return undefined;
  }
  let result: ts.Node | undefined;
  const visit = (node: ts.Node): void => {
    if (result) return;
    // A function declaration's name belongs to the scope it is declared in, so it is
    // checked before the rule below stops at the function's own boundary.
    if (ts.isFunctionDeclaration(node) && node.name?.text === name) {
      result = node;
      return;
    }
    // Nested functions and blocks declare their own names; do not look inside them.
    if (node !== scope && (ts.isFunctionLike(node) || ts.isBlock(node) || ts.isClassLike(node))) return;
    if (ts.isVariableDeclaration(node)) {
      const found = bindingNamed(node.name, name);
      if (found) {
        result = found === node.name ? node : found;
        return;
      }
    }
    node.forEachChild(visit);
  };
  scope.forEachChild(visit);
  return result;
}

function bindingNamed(binding: ts.BindingName, name: string): ts.Node | undefined {
  if (ts.isIdentifier(binding)) return binding.text === name ? binding : undefined;
  for (const element of binding.elements) {
    if (ts.isOmittedExpression(element)) continue;
    if (ts.isIdentifier(element.name) && element.name.text === name) return element;
    const nested = bindingNamed(element.name, name);
    if (nested) return nested;
  }
  return undefined;
}

/**
 * `event.data` in a `message` listener that never looks at `event.origin`.
 *
 * Checking the origin is the whole defence for this source: with it, the data
 * comes from a window the page chose to trust; without it, any page that holds a
 * reference to this window — an opener, a frame, a popup — chooses it.
 */
function isUnguardedMessageEvent(node: ts.Node): boolean {
  if (!ts.isIdentifier(node)) return false;
  const declaration = declarationFor(node);
  if (!declaration || !ts.isParameter(declaration)) return false;
  const handler = declaration.parent;
  if (!ts.isFunctionLike(handler) || handler.parameters[0] !== declaration) return false;
  if (!isMessageHandler(handler)) return false;
  const body = (handler as ts.FunctionLikeDeclaration).body;
  if (!body) return false;
  const eventName = node.text;
  let checksOrigin = false;
  walk(body, (inner) => {
    if (checksOrigin) return;
    if (ts.isPropertyAccessExpression(inner) && (inner.name.text === "origin" || inner.name.text === "source")) {
      const base = inner.expression;
      if (ts.isIdentifier(base) && base.text === eventName) checksOrigin = true;
    }
    // `const { origin, data } = event` reads it too.
    if (ts.isVariableDeclaration(inner) && ts.isObjectBindingPattern(inner.name) && inner.initializer && ts.isIdentifier(inner.initializer) && inner.initializer.text === eventName) {
      for (const element of inner.name.elements) {
        const property = element.propertyName ?? element.name;
        if (ts.isIdentifier(property) && (property.text === "origin" || property.text === "source")) checksOrigin = true;
      }
    }
  });
  return !checksOrigin;
}

function isMessageHandler(handler: ts.SignatureDeclaration): boolean {
  const parent = handler.parent;
  // addEventListener("message", (event) => ...)
  if (parent && ts.isCallExpression(parent) && calleeTail(parent) === "addEventListener") {
    const kind = parent.arguments[0];
    return Boolean(kind && ts.isStringLiteralLike(kind) && kind.text === "message" && parent.arguments[1] === handler);
  }
  // window.onmessage = (event) => ...
  if (parent && ts.isBinaryExpression(parent) && parent.right === handler && ts.isPropertyAccessExpression(parent.left)) {
    return parent.left.name.text === "onmessage";
  }
  return false;
}

/**
 * Has a guard that stops the function been applied to this binding?
 *
 * Counted only when an `if` whose failing branch returns or throws tests the
 * binding with something that constrains its *shape*: a regular expression, a
 * membership test, an equality against a literal, a prefix test, or a parsed URL's
 * origin or host. Anything weaker is not a guard. A guard that is wrong — testing
 * `startsWith("/")` and nothing else, say — is still counted here, because telling a
 * weak guard from a strong one is the job of the rule that knows the sink.
 */
export function clearedByGuard(declaration: ts.Node, use: ts.Node): boolean {
  if (!ts.isVariableDeclaration(declaration) || !ts.isIdentifier(declaration.name)) return false;
  const name = declaration.name.text;
  const scope = enclosingFunction(declaration) ?? declaration.getSourceFile();
  let guarded = false;
  walk(scope, (node) => {
    if (guarded || !ts.isIfStatement(node)) return;
    if (node.getStart() > use.getStart()) return;
    if (!terminates(node.thenStatement) && !(node.elseStatement && terminates(node.elseStatement))) return;
    let mentions = false;
    let constrains = false;
    walk(node.expression, (inner) => {
      if (ts.isIdentifier(inner) && inner.text === name) mentions = true;
      if (ts.isCallExpression(inner)) {
        const tail = calleeTail(inner);
        if (["test", "match", "has", "includes", "startsWith", "endsWith", "isSafeUrl", "isAllowed"].includes(tail)) constrains = true;
      }
      if (ts.isPropertyAccessExpression(inner) && ["origin", "host", "hostname", "protocol"].includes(inner.name.text)) constrains = true;
      if (ts.isBinaryExpression(inner) && [ts.SyntaxKind.EqualsEqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsEqualsToken].includes(inner.operatorToken.kind)) {
        if (ts.isStringLiteralLike(inner.left) || ts.isStringLiteralLike(inner.right)) constrains = true;
      }
    });
    if (mentions && constrains) guarded = true;
  });
  return guarded;
}

function terminates(statement: ts.Statement): boolean {
  let stops = false;
  walk(statement, (node) => {
    if (ts.isReturnStatement(node) || ts.isThrowStatement(node)) stops = true;
  });
  return stops;
}
