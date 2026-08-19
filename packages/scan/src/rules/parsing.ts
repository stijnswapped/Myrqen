import ts from "typescript";
import {
  calleeName,
  calleeTail,
  collect,
  enclosingFunction,
  expressionName,
  functionName,
  isConstantString,
  isStringLike,
  literalTextOf,
  walk
} from "../ast/helpers.js";
import type { ParsedFile } from "../ast/parse.js";
import { analyzeFunction, functionsIn, resolveExpression, rootOf, taintOrigin, type TaintScope } from "../ast/taint.js";
import {
  locationOf,
  routeFor,
  sourceEvidence,
  taintEvidence,
  type Rule,
  type RuleContext
} from "./context.js";

/**
 * Injection through parsers and interpreters.
 *
 * Every rule in this file follows the same shape: the *sink* is a parser, a
 * template compiler, a query filter, or an interpreter, and the defect is that
 * caller-controlled data reaches it in a position where it changes meaning
 * rather than supplying a value. Each rule therefore has to know two things a
 * pattern scanner does not: which argument position carries meaning, and what
 * the correct form of the same call looks like — because the correct form is
 * what most of this code actually is.
 */

/* ------------------------------------------------------------------ *
 * Scope cache
 *
 * A sink is judged with the tightest function scope that lexically contains
 * it. Rules elsewhere in the engine iterate `functionsIn` and let the engine's
 * dedupe drop the duplicate reports that produces; judging with the innermost
 * scope instead means a rule reports once, with the most complete taint
 * picture, and does not depend on report ordering.
 * ------------------------------------------------------------------ */

interface ScopeEntry {
  fn: ts.Node;
  scope: TaintScope;
  span: number;
}

const scopeCache = new WeakMap<ts.SourceFile, ScopeEntry[]>();

function scopesOf(file: ParsedFile): ScopeEntry[] {
  const cached = scopeCache.get(file.source);
  if (cached) return cached;
  const entries = functionsIn(file.source).map((fn) => ({
    fn,
    scope: analyzeFunction(file, fn),
    span: fn.end - fn.pos
  }));
  entries.sort((a, b) => a.span - b.span);
  scopeCache.set(file.source, entries);
  return entries;
}

function contains(outer: ts.Node, inner: ts.Node): boolean {
  return inner.pos >= outer.pos && inner.end <= outer.end;
}

/** Scopes that contain this node, innermost first. */
function scopesContaining(context: RuleContext, node: ts.Node): ScopeEntry[] {
  return scopesOf(context.file).filter((entry) => contains(entry.fn, node));
}

/**
 * Why the expression is caller-controlled, judged in the tightest scope that
 * contains it. Returns the first origin any containing scope can prove, so a
 * handler nested inside a plugin factory is still analysed with its own
 * parameters.
 */
function taintAt(context: RuleContext, site: ts.Node, expression: ts.Node): string | null {
  for (const entry of scopesContaining(context, site)) {
    const origin = taintOrigin(expression, entry.scope);
    if (origin) return origin;
  }
  return null;
}

function innermostScope(context: RuleContext, node: ts.Node): TaintScope | null {
  const entry = scopesContaining(context, node).find((candidate) => (candidate.fn as ts.FunctionLikeDeclaration).body);
  return entry ? entry.scope : null;
}

/* ------------------------------------------------------------------ *
 * Route attribution
 *
 * BELONGS UPSTREAM in `ast/routes.ts`. Route discovery currently recognises
 * framework registration, `method === "GET /x"` comparisons, regex `.test`
 * dispatch, and file-based routing, and `routeFor` attributes a sink to the
 * nearest route declared *above* it. Neither covers the shape every hand-rolled
 * Node server uses: handlers declared above a dispatch table, a switch, or an
 * `if` chain that calls them. Without this, a finding in such a handler carries
 * no route, which is the first thing a reader needs in order to probe it.
 * ------------------------------------------------------------------ */

const METHOD_AND_PATH = /^(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+(\/\S*)$/;
const HTTP_METHOD_LITERAL = /^(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)$/;
const REGISTRATION_METHODS = new Set(["get", "post", "put", "patch", "delete", "options", "head", "all", "use"]);

/** Parameters that carry framework plumbing rather than a path segment. */
const PLUMBING_PARAMETER =
  /^_?(req|request|res|response|reply|ctx|context|next|url|event|options|opts|body|payload|parent|info|args|input|done)$/i;

/** Expressions that plausibly hold the request path. */
const PATH_BEARING = /pathname|\burl\b|\bpath\b|\broute\b|\btarget\b|\bendpoint\b|\bhref\b/i;

interface DispatchEntry {
  method: string;
  path: string;
  /** Handlers this route dispatches to by name. */
  handlers: Set<string>;
  /** The branch or callback that implements the route, when it is inline. */
  node?: ts.Node;
}

const dispatchCache = new WeakMap<ts.SourceFile, DispatchEntry[]>();
const declarationCache = new WeakMap<ts.SourceFile, Map<string, ts.Expression>>();

/** Every `const x = <expression>` in the file, so a constant can be resolved. */
function declarationsIn(source: ts.SourceFile): Map<string, ts.Expression> {
  const cached = declarationCache.get(source);
  if (cached) return cached;
  const map = new Map<string, ts.Expression>();
  walk(source, (node) => {
    if (!ts.isVariableDeclaration(node) || !ts.isIdentifier(node.name) || !node.initializer) return;
    map.set(node.name.text, node.initializer);
  });
  declarationCache.set(source, map);
  return map;
}

/** Functions called by name inside this node. */
function calledByName(node: ts.Node): Set<string> {
  const names = new Set<string>();
  walk(node, (inner) => {
    if (ts.isCallExpression(inner) && ts.isIdentifier(inner.expression)) names.add(inner.expression.text);
  });
  return names;
}

/** `^\/api\/workspaces\/([\w-]{6,40})\/preferences$` becomes `/api/workspaces/:id/preferences`. */
function pathFromRegexSource(pattern: string): string | null {
  const body = pattern.replace(/^\^/, "").replace(/\$$/, "").replace(/\\\//g, "/");
  if (!body.startsWith("/")) return null;
  const segments = body
    .slice(1)
    .split("/")
    .filter((segment) => segment.length > 0)
    .map((segment) => {
      const named = /^\(\?<([A-Za-z_][A-Za-z0-9_]*)>.*\)[?+*]?$/.exec(segment);
      if (named) return `:${named[1]}`;
      return /[\\[\](){}+*?|]/.test(segment) ? ":id" : segment;
    });
  return segments.length === 0 ? "/" : `/${segments.join("/")}`;
}

/** The source of a regular expression written inline or held in a constant. */
function regexSourceOf(node: ts.Node, source: ts.SourceFile, depth = 0): string | null {
  if (ts.isRegularExpressionLiteral(node)) {
    const text = node.getText(source);
    const end = text.lastIndexOf("/");
    return end > 0 ? text.slice(1, end) : null;
  }
  if (ts.isNewExpression(node) && expressionName(node.expression) === "RegExp") {
    const first = node.arguments?.[0];
    return first && ts.isStringLiteralLike(first) ? first.text : null;
  }
  if (ts.isIdentifier(node) && depth < 3) {
    const initializer = declarationsIn(source).get(node.text);
    return initializer ? regexSourceOf(initializer, source, depth + 1) : null;
  }
  return null;
}

/** The method and path an `if` condition selects, when it selects one. */
function conditionRoute(condition: ts.Expression, source: ts.SourceFile): { method?: string; path?: string } {
  let method: string | undefined;
  let path: string | undefined;

  const pathFromMatcher = (call: ts.CallExpression): string | undefined => {
    const tail = calleeTail(call);
    if (tail !== "test" && tail !== "exec" && tail !== "match") return undefined;
    if (!ts.isPropertyAccessExpression(call.expression)) return undefined;
    const subject = call.arguments[0]?.getText(source) ?? "";
    const receiver = call.expression.expression;
    // `PATTERN.test(url.pathname)` and `url.pathname.match(PATTERN)` are the same route.
    const pattern =
      regexSourceOf(receiver, source) ?? (tail === "match" ? regexSourceOf(call.arguments[0] ?? receiver, source) : null);
    if (!pattern) return undefined;
    const tested = tail === "match" ? receiver.getText(source) : subject;
    if (!PATH_BEARING.test(tested)) return undefined;
    return pathFromRegexSource(pattern) ?? undefined;
  };

  walk(condition, (node) => {
    if (ts.isCallExpression(node)) {
      path ??= pathFromMatcher(node);
      return;
    }
    // An identifier in the condition may hold the match result: `if (matched && ...)`.
    if (ts.isIdentifier(node) && !path) {
      const initializer = declarationsIn(source).get(node.text);
      if (initializer && ts.isCallExpression(initializer)) path ??= pathFromMatcher(initializer);
      return;
    }
    if (!ts.isBinaryExpression(node)) return;
    const isEquality =
      node.operatorToken.kind === ts.SyntaxKind.EqualsEqualsEqualsToken ||
      node.operatorToken.kind === ts.SyntaxKind.EqualsEqualsToken;
    if (!isEquality) return;
    for (const [side, other] of [
      [node.left, node.right],
      [node.right, node.left]
    ] as Array<[ts.Expression, ts.Expression]>) {
      const literal = literalTextOf(side);
      if (!literal) continue;
      if (HTTP_METHOD_LITERAL.test(literal) && /method/i.test(other.getText(source))) {
        method ??= literal;
        continue;
      }
      if (!literal.startsWith("/")) continue;
      // The other side has to be the request path, whether read inline or held
      // in a local: `target === "/x"` where `target` came from `url.pathname`.
      const otherText = other.getText(source);
      const resolved = ts.isIdentifier(other) ? declarationsIn(source).get(other.text)?.getText(source) ?? "" : "";
      if (PATH_BEARING.test(otherText) || PATH_BEARING.test(resolved)) path ??= literal;
    }
  });

  return { ...(method ? { method } : {}), ...(path ? { path } : {}) };
}

/**
 * A router's own prefix, when it is declared in this file.
 *
 * `new Router({ prefix: "/notification-preferences" })` followed by
 * `router.patch("/", handler)` is one route, and reporting it as `PATCH /` sends a
 * reader to an endpoint that does not exist. Where the mount happens in another
 * module the engine still cannot know it, and says so in its coverage notes.
 */
function withPrefix(receiver: string, path: string, source: ts.SourceFile): string {
  if (!receiver) return path;
  const declaration = declarationsIn(source).get(receiver);
  if (!declaration) return path;
  let prefix: string | null = null;
  walk(declaration, (node) => {
    if (prefix || !ts.isPropertyAssignment(node)) return;
    const key = ts.isIdentifier(node.name) || ts.isStringLiteralLike(node.name) ? node.name.text : "";
    if (key !== "prefix" && key !== "basePath" && key !== "base") return;
    const value = literalTextOf(node.initializer);
    if (value && value.startsWith("/")) prefix = value;
  });
  if (!prefix) return path;
  const base = (prefix as string).replace(/\/$/, "");
  if (path === "/") return base;
  return path.startsWith(base) ? path : `${base}${path}`;
}

/**
 * Dispatch shapes that route discovery does not model: a table keyed by
 * `"METHOD /path"`, a switch over the same string, an `if` chain, and framework
 * registration whose handler is a named function declared elsewhere.
 */
function dispatchTable(context: RuleContext): DispatchEntry[] {
  const source = context.file.source;
  const cached = dispatchCache.get(source);
  if (cached) return cached;
  const entries: DispatchEntry[] = [];

  for (const call of collect(source, ts.isCallExpression)) {
    const tail = calleeTail(call).toLowerCase();
    if (!REGISTRATION_METHODS.has(tail)) continue;
    const first = call.arguments[0];
    if (!first) continue;
    const literal = literalTextOf(first);
    if (!literal || !literal.startsWith("/")) continue;
    const handlers = new Set<string>();
    let inline: ts.Node | undefined;
    for (const argument of call.arguments.slice(1)) {
      if (ts.isIdentifier(argument)) handlers.add(argument.text);
      if (ts.isArrayLiteralExpression(argument)) {
        for (const element of argument.elements) if (ts.isIdentifier(element)) handlers.add(element.text);
      }
      // Middleware come first and the handler last, so the last function
      // argument is the one whose body implements the route.
      if (ts.isArrowFunction(argument) || ts.isFunctionExpression(argument)) inline = argument;
    }
    const receiver = ts.isPropertyAccessExpression(call.expression)
      ? call.expression.expression.getText(source)
      : "";
    entries.push({
      method: tail === "use" || tail === "all" ? "ANY" : tail.toUpperCase(),
      path: withPrefix(receiver, literal, source),
      handlers,
      ...(inline ? { node: inline } : {})
    });
  }

  for (const property of collect(source, ts.isPropertyAssignment)) {
    if (!ts.isStringLiteralLike(property.name)) continue;
    const match = METHOD_AND_PATH.exec(property.name.text);
    if (!match) continue;
    const handlers = new Set<string>();
    if (ts.isIdentifier(property.initializer)) handlers.add(property.initializer.text);
    entries.push({
      method: match[1]!,
      path: match[2]!,
      handlers,
      ...(ts.isArrowFunction(property.initializer) || ts.isFunctionExpression(property.initializer)
        ? { node: property.initializer }
        : {})
    });
  }

  for (const clause of collect(source, ts.isCaseClause)) {
    const literal = literalTextOf(clause.expression);
    if (!literal) continue;
    const match = METHOD_AND_PATH.exec(literal);
    if (!match) continue;
    entries.push({ method: match[1]!, path: match[2]!, handlers: calledByName(clause), node: clause });
  }

  for (const statement of collect(source, ts.isIfStatement)) {
    const { method, path } = conditionRoute(statement.expression, source);
    if (!path) continue;
    entries.push({
      method: method ?? "ANY",
      path,
      handlers: calledByName(statement.thenStatement),
      node: statement.thenStatement
    });
  }

  dispatchCache.set(source, entries);
  return entries;
}

/** The nearest enclosing function that has a name we can report. */
function enclosingNamed(node: ts.Node): ts.Node | undefined {
  let current = enclosingFunction(node);
  while (current) {
    if (functionName(current)) return current;
    current = enclosingFunction(current);
  }
  return undefined;
}

/**
 * Name the path parameters after the arguments the application itself uses.
 *
 * A regex route cannot say what its capture means, but `patchPreferences(request,
 * response, workspaceId)` does: the handler's own parameter names are the names
 * the codebase gives those segments, and reporting `/:workspaceId` rather than
 * `/:id` is the difference between a route a reader recognises and one they have
 * to go and look up.
 */
function nameParameters(path: string, handler: ts.Node | undefined): string {
  if (!handler) return path;
  const dynamic = path.split("/").filter((segment) => segment.startsWith(":")).length;
  if (dynamic === 0) return path;
  const parameters = ((handler as ts.FunctionLikeDeclaration).parameters ?? [])
    .filter((parameter) => ts.isIdentifier(parameter.name) && !PLUMBING_PARAMETER.test(parameter.name.text))
    .map((parameter) => (parameter.name as ts.Identifier).text);
  if (parameters.length !== dynamic) return path;
  let index = 0;
  return path
    .split("/")
    .map((segment) => (segment.startsWith(":") ? `:${parameters[index++]}` : segment))
    .join("/");
}

function formatRoute(method: string, path: string): string {
  return method === "ANY" ? path : `${method} ${path}`;
}

/** Does this file define GraphQL resolvers? */
function isGraphqlModule(context: RuleContext): boolean {
  const text = context.file.text;
  if (!/graphql|gql`|apollo/i.test(text)) return false;
  return /\b(typeDefs|resolvers|makeExecutableSchema|buildSchema)\b/.test(text);
}

/** Is this node inside a resolver map, rather than schema or plumbing code? */
function inResolverMap(node: ts.Node): boolean {
  let current: ts.Node | undefined = node.parent;
  while (current) {
    if (
      (ts.isPropertyAssignment(current) || ts.isMethodDeclaration(current)) &&
      ts.isIdentifier(current.name) &&
      /^(Query|Mutation|Subscription)$/.test(current.name.text)
    ) {
      return true;
    }
    current = current.parent;
  }
  return false;
}

/**
 * The route a sink is reachable from. Tries containment in a handler body, then
 * dispatch by handler name, then the nearest route declared above, and finally
 * the GraphQL transport convention: a resolver is reached through the single
 * GraphQL endpoint, which is what a reader has to send the probe to.
 */
function attributedRoute(context: RuleContext, node: ts.Node): string | undefined {
  const entries = dispatchTable(context);
  for (const entry of entries) {
    if (entry.node && contains(entry.node, node)) return formatRoute(entry.method, entry.path);
  }
  for (const hint of context.routes) {
    if (hint.node && contains(hint.node, node)) return formatRoute(hint.method, hint.path);
  }

  const handler = enclosingNamed(node);
  const name = handler ? functionName(handler) : undefined;
  if (name) {
    for (const hint of context.routes) {
      if (!hint.node || !calledByName(hint.node).has(name)) continue;
      return formatRoute(hint.method, nameParameters(hint.path, handler));
    }
    for (const entry of entries) {
      if (!entry.handlers.has(name)) continue;
      return formatRoute(entry.method, nameParameters(entry.path, handler));
    }
  }

  const nearest = routeFor(context, node);
  if (nearest) return nearest;
  if (isGraphqlModule(context) && inResolverMap(node)) return "POST /graphql";
  return undefined;
}

function withRoute(context: RuleContext, node: ts.Node): { route?: string } {
  const route = attributedRoute(context, node);
  return route ? { route } : {};
}

/* ------------------------------------------------------------------ *
 * Shared predicates
 * ------------------------------------------------------------------ */

/** Names this file binds from a module whose specifier matches. */
function importedBindings(context: RuleContext, pattern: RegExp): Set<string> {
  const names = new Set<string>();
  for (const statement of context.file.source.statements) {
    if (ts.isImportDeclaration(statement) && ts.isStringLiteralLike(statement.moduleSpecifier)) {
      if (!pattern.test(statement.moduleSpecifier.text)) continue;
      const clause = statement.importClause;
      if (!clause) continue;
      if (clause.name) names.add(clause.name.text);
      const bindings = clause.namedBindings;
      if (bindings && ts.isNamespaceImport(bindings)) names.add(bindings.name.text);
      if (bindings && ts.isNamedImports(bindings)) {
        for (const element of bindings.elements) names.add(element.name.text);
      }
    }
  }
  for (const declaration of collect(context.file.source, ts.isVariableDeclaration)) {
    const initializer = declaration.initializer;
    if (!initializer || !ts.isCallExpression(initializer) || calleeName(initializer) !== "require") continue;
    const specifier = initializer.arguments[0];
    if (!specifier || !ts.isStringLiteralLike(specifier) || !pattern.test(specifier.text)) continue;
    if (ts.isIdentifier(declaration.name)) names.add(declaration.name.text);
    if (ts.isObjectBindingPattern(declaration.name)) {
      for (const element of declaration.name.elements) {
        if (ts.isIdentifier(element.name)) names.add(element.name.text);
      }
    }
  }
  return names;
}

/** Does the file pull in a module whose specifier matches? */
function importsModule(context: RuleContext, pattern: RegExp): boolean {
  for (const statement of context.file.source.statements) {
    if (ts.isImportDeclaration(statement) && ts.isStringLiteralLike(statement.moduleSpecifier)) {
      if (pattern.test(statement.moduleSpecifier.text)) return true;
    }
  }
  for (const call of collect(context.file.source, ts.isCallExpression)) {
    if (calleeName(call) !== "require") continue;
    const first = call.arguments[0];
    if (first && ts.isStringLiteralLike(first) && pattern.test(first.text)) return true;
  }
  return false;
}

/** Terminating type guards that pin a value to a scalar before it is used. */
function scalarGuarded(scope: TaintScope | null, name: string | null): boolean {
  if (!scope || !name) return false;
  const body = (scope.fn as ts.FunctionLikeDeclaration).body;
  if (!body) return false;
  let guarded = false;
  walk(body, (node) => {
    if (guarded || !ts.isIfStatement(node)) return;
    let terminates = false;
    walk(node.thenStatement, (inner) => {
      if (ts.isReturnStatement(inner) || ts.isThrowStatement(inner)) terminates = true;
    });
    if (!terminates) return;
    const condition = node.expression.getText(scope.fn.getSourceFile());
    const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    if (
      new RegExp(`typeof\\s+${escaped}\\b`).test(condition) ||
      new RegExp(`Array\\.isArray\\(\\s*${escaped}\\b`).test(condition) ||
      new RegExp(`Number\\.is(Integer|Finite|SafeInteger)\\(\\s*${escaped}\\b`).test(condition) ||
      new RegExp(`\\b${escaped}\\s+instanceof\\b`).test(condition)
    ) {
      guarded = true;
    }
  });
  return guarded;
}

/* ------------------------------------------------------------------ *
 * template_injection
 * ------------------------------------------------------------------ */

/** Template engines whose compile step turns a string into a program. */
const TEMPLATE_ENGINE_MODULE =
  /^(handlebars|hbs|express-handlebars|ejs|pug|jade|nunjucks|mustache|hogan\.js|dot|dotjs|eta|liquidjs|liquid-node|twig|squirrelly|art-template|vash|swig|dustjs-linkedin|underscore|lodash|lodash\.template)(\/|$)/i;

const TEMPLATE_ENGINE_RECEIVER =
  /(^|\.)(handlebars|hbs|ejs|pug|jade|nunjucks|mustache|hogan|dot|eta|liquid|twig|squirrelly|sqrl|art|vash|swig|dust|underscore|_|lodash|templates?|engine|renderer)$/i;

/** Calls that compile a template string. The template is always argument zero. */
const COMPILE_TAILS = new Set(["compile", "precompile", "template", "renderString", "compileToString", "parseAndRender", "render"]);

/** Delimiters that say a string is a template program rather than plain source. */
const TEMPLATE_DELIMITERS = /\{\{|<%|\{%/;

export const templateInjection: Rule = {
  id: "template-injection",
  category: "template_injection",
  describes: "caller-controlled data compiled as a template program",
  run(context: RuleContext) {
    // Only a binding that actually came from a template engine counts. A project
    // helper called `compile` in a file that happens to import lodash is not a
    // template compiler, and treating it as one would be noise in every codebase.
    const engines = importedBindings(context, TEMPLATE_ENGINE_MODULE);

    for (const call of collect(context.file.source, ts.isCallExpression)) {
      const tail = calleeTail(call);
      if (!COMPILE_TAILS.has(tail)) continue;

      const receiver = ts.isPropertyAccessExpression(call.expression)
        ? expressionName(call.expression.expression)
        : null;
      // A bare `compile(markup)` counts only when the callee itself was imported
      // from an engine; `render` is far too common a name to accept otherwise.
      const isEngineCall = receiver
        ? TEMPLATE_ENGINE_RECEIVER.test(receiver) || engines.has(receiver.split(".")[0] ?? receiver)
        : ts.isIdentifier(call.expression) && engines.has(call.expression.text);
      if (!isEngineCall) continue;

      const template = call.arguments[0];
      if (!template) continue;
      // A fixed template with caller-supplied *data* is the correct usage: the
      // data is escaped by the engine and cannot become part of the program.
      if (isConstantString(template)) continue;

      const origin = taintAt(context, call, template);
      if (!origin) continue;

      const sink = `${receiver ? `${receiver}.` : ""}${tail}()`;
      report(context, call, sink, origin, "engine");
    }

    // A hand-rolled renderer: caller markup interpolated into source given to
    // `new Function`. The compiled string carries template delimiters, which is
    // what separates a renderer from the arbitrary evaluation the code-injection
    // rule reports.
    for (const expression of collect(context.file.source, ts.isNewExpression)) {
      if (expressionName(expression.expression) !== "Function") continue;
      const source = (expression.arguments ?? []).find((argument) =>
        TEMPLATE_DELIMITERS.test(argument.getText(context.file.source))
      );
      if (!source) continue;
      const origin = taintAt(context, expression, source);
      if (!origin) continue;
      report(context, expression, "new Function", origin, "hand-rolled");
    }

    function report(
      ruleContext: RuleContext,
      node: ts.Node,
      sink: string,
      origin: string,
      kind: "engine" | "hand-rolled"
    ): void {
      ruleContext.report({
        ruleId: "template-injection",
        category: "template_injection",
        title: `Caller-controlled markup is compiled as a template by ${sink}`,
        severity: "critical",
        verification: "strong_evidence",
        summary: `A value derived from ${origin} is passed to ${sink} as the template itself rather than as the data the template renders. ${
          kind === "engine"
            ? "The caller therefore supplies the template program: its expressions, its helper invocations, and its property lookups all run server-side."
            : "The caller therefore supplies part of a function body that is compiled and run server-side."
        }`,
        impact:
          "Server-side template injection in this family of engines reaches JavaScript through helper and prototype lookups, so the practical outcome is code execution in the application process — and short of that, disclosure of every value in the render context.",
        remediation:
          "Compile templates from source the application controls: load them from the repository or a template store at boot, keep a fixed set the request may select by key, and pass everything from the request as render *data* so the engine escapes it. If authors genuinely need to edit templates, compile them in a separate sandboxed worker with no filesystem or network access and treat the result as untrusted.",
        verificationPlan:
          "Post a template body containing an engine expression that would resolve a constructor or read a context object (for example `{{#with \"s\" as |s|}}` chains, or `<%= process.env %>`), and confirm the response contains the literal text rather than an evaluated result.",
        taxonomy: ["CWE-1336", "CWE-94", "OWASP-A03"],
        location: locationOf(ruleContext, node),
        ...withRoute(ruleContext, node),
        evidence: [
          sourceEvidence(ruleContext, node, `${sink} receives the template string from the request.`),
          taintEvidence(origin, sink)
        ],
        reasoning: `Taint from ${origin} reaches the template argument of ${sink}; the argument is not a constant and is not read from a template store.`
      });
    }
  }
};

/* ------------------------------------------------------------------ *
 * xml_external_entity
 * ------------------------------------------------------------------ */

/** Parser options that turn a document's own DOCTYPE into a fetch instruction. */
const ENTITY_OPTIONS = new Map<string, string>([
  ["noent", "entity substitution (`noent`)"],
  ["dtdload", "external DTD loading (`dtdload`)"],
  ["dtdvalid", "DTD validation, which loads the DTD (`dtdvalid`)"],
  ["dtdattr", "DTD default attributes, which loads the DTD (`dtdattr`)"],
  ["replaceEntities", "entity substitution (`replaceEntities`)"],
  ["resolveExternals", "external reference resolution (`resolveExternals`)"],
  ["externalEntities", "external entity resolution (`externalEntities`)"],
  ["loadExternalDtd", "external DTD loading (`loadExternalDtd`)"],
  ["expandEntities", "entity expansion (`expandEntities`)"],
  ["resolveEntities", "entity resolution (`resolveEntities`)"]
]);

const XML_MODULE = /(libxmljs|xmldom|@xmldom|\bsax\b|expat|xml2js|fast-xml-parser|libxslt|xpath|node-xml|xmlbuilder)/i;
const XML_CALL = /xml|dom|sax|expat|parse|dtd/i;

export const xmlExternalEntity: Rule = {
  id: "xml-external-entity",
  category: "xml_external_entity",
  describes: "an XML parser configured to resolve external entities or load DTDs",
  run(context: RuleContext) {
    const xmlImported = importsModule(context, XML_MODULE);

    const candidates: ts.Node[] = [
      ...collect(context.file.source, ts.isCallExpression),
      ...collect(context.file.source, ts.isNewExpression)
    ];

    for (const node of candidates) {
      const call = node as ts.CallExpression | ts.NewExpression;
      const name = ts.isCallExpression(call) ? calleeName(call) : expressionName(call.expression);
      if (!XML_CALL.test(name) && !xmlImported) continue;

      const argumentList: readonly ts.Expression[] = call.arguments ? [...call.arguments] : [];
      const options = argumentList.find((argument): argument is ts.ObjectLiteralExpression =>
        ts.isObjectLiteralExpression(argument)
      );
      if (!options) continue;

      const enabled: string[] = [];
      let networkDisabled = false;
      for (const property of options.properties) {
        if (!ts.isPropertyAssignment(property)) continue;
        const key = ts.isIdentifier(property.name) || ts.isStringLiteralLike(property.name) ? property.name.text : "";
        const value = property.initializer.kind === ts.SyntaxKind.TrueKeyword;
        if (key === "nonet" && value) networkDisabled = true;
        const description = ENTITY_OPTIONS.get(key);
        // Only an explicitly enabled flag counts. The correct form of this call
        // sets the same keys to false, and reporting that would be a bug.
        if (description && value) enabled.push(description);
      }
      if (enabled.length === 0) continue;
      // The parser has to be an XML parser, not any call that happens to take an
      // options object with a matching key.
      if (!xmlImported && !XML_CALL.test(name)) continue;

      const document = call.arguments?.[0];
      const origin = document ? taintAt(context, call, document) : null;
      const sink = ts.isCallExpression(call) ? `${name}()` : `new ${name}()`;

      context.report({
        ruleId: "xml-external-entity",
        category: "xml_external_entity",
        title: `XML parser at ${sink} resolves external entities`,
        severity: origin ? "high" : "medium",
        verification: origin ? "strong_evidence" : "needs_review",
        summary: `${sink} is configured with ${enabled.join(" and ")} enabled${
          origin ? `, and the document it parses is derived from ${origin}` : ", so any document reaching it is parsed with its own DOCTYPE honoured"
        }. A \`<!DOCTYPE>\` declaring a SYSTEM entity is therefore resolved while the document is being parsed.${
          networkDisabled
            ? " The call sets `nonet`, so outbound fetches are blocked, but local `file://` entities still resolve."
            : ""
        }`,
        impact: networkDisabled
          ? "An attacker reads any file the application process can read — configuration, credentials, keys — by declaring it as an entity and having the parsed value echoed back in the mapped result."
          : "An attacker reads local files and makes the server issue requests to internal addresses it can reach but they cannot, turning the importer into a proxy into the private network. Entity expansion also gives a cheap denial of service.",
        remediation:
          "Turn the flags off: parse with entity substitution and DTD loading disabled and network access blocked (`noent: false, dtdload: false, dtdattr: false, dtdvalid: false, nonet: true`). If a supplier's document genuinely depends on shared code lists, resolve those from a copy the application ships rather than from the document's own DOCTYPE.",
        verificationPlan:
          "Post a document whose DOCTYPE declares `<!ENTITY x SYSTEM \"file:///etc/hostname\">` and references `&x;` in a mapped field, then confirm the stored or echoed value contains the literal entity reference and that no file contents appear. Repeat with an `http://` entity pointing at a request-logging host and confirm no request arrives.",
        taxonomy: ["CWE-611", "CWE-827", "OWASP-A05"],
        location: locationOf(context, call),
        ...withRoute(context, call),
        evidence: [
          sourceEvidence(context, call, `The parser options enable ${enabled.join(" and ")}.`),
          ...(origin ? [taintEvidence(origin, sink)] : [])
        ],
        reasoning: `${sink} is called with ${enabled.length} entity-resolving option(s) set to true${
          origin ? `, and the document argument is tainted from ${origin}` : ", with no proof in this file that the document is trusted"
        }.`
      });
    }
  }
};

/* ------------------------------------------------------------------ *
 * nosql_injection
 * ------------------------------------------------------------------ */

/** Query methods and the argument positions that carry query meaning. */
const MONGO_QUERY_METHODS = new Map<string, number[]>([
  ["find", [0]],
  ["findOne", [0]],
  ["findOneAndUpdate", [0, 1]],
  ["findOneAndDelete", [0]],
  ["findOneAndReplace", [0]],
  ["updateOne", [0, 1]],
  ["updateMany", [0, 1]],
  ["replaceOne", [0]],
  ["deleteOne", [0]],
  ["deleteMany", [0]],
  ["countDocuments", [0]],
  ["count", [0]],
  ["findAndModify", [0]],
  ["distinct", [1]]
]);

/** Calls whose result is the request body as it arrived. */
const RAW_BODY_READER = /^(json|text|formData|arrayBuffer|blob|buffer|body|rawBody|parseBody|readBody|readJson|readRaw|readAll|collectJson|collectBody|getBody)$/i;

/** Calls that leave a value unable to carry a query operator. */
const SCALAR_COERCION =
  /^(String|Number|parseInt|parseFloat|Boolean|BigInt|ObjectId|toObjectId|toString|trim|toLowerCase|toUpperCase|normalize|padStart|padEnd|charAt|toFixed|valueOf|split|slice|substring|substr|replace|replaceAll|join)$/;

/** Operator keys whose value is itself interpreted, not matched. */
const EVALUATED_OPERATORS = new Set(["$where", "$expr", "$function", "$accumulator", "$jsonSchema"]);

interface FilterFlow {
  /** Where a reader should look: the spread, the property, or the argument. */
  node: ts.Node;
  /** The expression that carries the caller's value, for guard checks. */
  value: ts.Node;
  origin: string;
  kind: "spread" | "value" | "whole";
  key?: string;
  evaluated?: boolean;
}

/** Request properties the caller writes. */
const CALLER_DATA_SEGMENT = /\.(body|query|params|search|form|payload|input|variables|args|cookies?|headers?)\b/;

/** Request properties that can only ever be a string, whatever the caller sends. */
const SCALAR_ONLY_SOURCE = /\.(params?|headers?|cookies?)\b/;

/** Request properties that can carry a JSON object, and therefore an operator. */
const OBJECT_CAPABLE_SOURCE = /\.(body|query|search|form|payload|input|variables|args)\b|\(inbound request\)|request body\)/;

/**
 * Can this source carry an object at all?
 *
 * A path parameter, a header, and a cookie are strings by the time any framework
 * hands them over, so they cannot become `{"$ne": null}` however they are used.
 * A JSON body can, and so can a query string under Express's default parser.
 * Reporting the string-only sources would mean reporting every lookup by id.
 *
 * BELONGS UPSTREAM: `TaintedRoot` records a human-readable origin but not the
 * *kind* of source, so this has to re-read the origin text. A `kind` field on the
 * root would let every rule make this distinction properly.
 */
function objectCapable(text: string): boolean {
  if (OBJECT_CAPABLE_SOURCE.test(text)) return true;
  return !SCALAR_ONLY_SOURCE.test(text);
}

/**
 * Caller data that keeps its own shape.
 *
 * A Mongo filter is only injectable when the caller controls an *object*: a
 * string can only ever be a value to match. So the question is not "is this
 * tainted" but "did anything between the request and the filter turn it into a
 * scalar or rebuild it". A coercion, a validator, and a project helper that
 * copies known keys all break the flow; a body reader does not.
 */
function callerShapedOrigin(node: ts.Node, scope: TaintScope, depth = 0): string | null {
  if (depth > 6) return null;
  if (
    ts.isParenthesizedExpression(node) ||
    ts.isNonNullExpression(node) ||
    ts.isAwaitExpression(node) ||
    ts.isAsExpression(node)
  ) {
    return callerShapedOrigin(node.expression, scope, depth + 1);
  }
  if (ts.isIdentifier(node)) {
    if (scope.cleared.has(node.text)) return null;
    const initializer = scope.initializers.get(node.text);
    if (initializer) return callerShapedOrigin(initializer, scope, depth + 1);
    const root = scope.roots.get(node.text);
    if (!root) return null;
    return objectCapable(root.origin) ? root.origin : null;
  }
  if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
    const path = node.getText();
    const root = rootOf(node);
    if (!root || scope.cleared.has(root)) return null;
    // A property read off a local binding is only caller-shaped if the binding is.
    const initializer = scope.initializers.get(root);
    if (initializer) return callerShapedOrigin(initializer, scope, depth + 1);
    const entry = scope.roots.get(root);
    if (!entry) return null;
    // The request object itself is a mixture: `request.body` is the caller's, and
    // `request.user` is whatever the authentication middleware decorated it with.
    // Treating the whole object as attacker-controlled would report every lookup
    // by session id as an injection.
    if (entry.declaration === scope.fn && !CALLER_DATA_SEGMENT.test(path)) return null;
    return objectCapable(path) && objectCapable(entry.origin) ? entry.origin : null;
  }
  if (ts.isBinaryExpression(node)) {
    const operator = node.operatorToken.kind;
    // `filter ?? {}` and `filter || {}` are still the caller's object.
    if (operator === ts.SyntaxKind.QuestionQuestionToken || operator === ts.SyntaxKind.BarBarToken) {
      return callerShapedOrigin(node.left, scope, depth + 1) ?? callerShapedOrigin(node.right, scope, depth + 1);
    }
    // Any arithmetic or concatenation produces a scalar.
    return null;
  }
  if (ts.isConditionalExpression(node)) {
    return (
      callerShapedOrigin(node.whenTrue, scope, depth + 1) ?? callerShapedOrigin(node.whenFalse, scope, depth + 1)
    );
  }
  if (ts.isCallExpression(node)) {
    const tail = calleeTail(node);
    const name = calleeName(node);
    if (SCALAR_COERCION.test(tail) || SCALAR_COERCION.test(name)) return null;
    // A body reader hands the payload back as it arrived, including its keys.
    if (RAW_BODY_READER.test(tail) || name === "JSON.parse") {
      for (const argument of node.arguments) {
        const origin = callerShapedOrigin(argument, scope, depth + 1);
        if (origin) return origin;
      }
      const receiver = ts.isPropertyAccessExpression(node.expression) ? node.expression.expression : null;
      const direct = receiver ? taintOrigin(receiver, scope) : null;
      if (direct) return direct;
      return taintOrigin(node, scope);
    }
    // Anything else — a validator, a schema parse, a helper that copies the keys
    // it recognises — is a step this engine cannot see through. Reporting through
    // it would mean reporting every correctly validated filter in the codebase.
    return null;
  }
  return null;
}

/** Caller-controlled parts of a filter or update document. */
function filterFlows(argument: ts.Expression, scope: TaintScope, depth = 0): FilterFlow[] {
  const flows: FilterFlow[] = [];
  const resolved = resolveExpression(argument, scope);

  if (ts.isObjectLiteralExpression(resolved)) {
    for (const property of resolved.properties) {
      if (ts.isSpreadAssignment(property)) {
        const origin = callerShapedOrigin(property.expression, scope);
        if (origin) flows.push({ node: property, value: property.expression, origin, kind: "spread" });
        continue;
      }
      if (ts.isShorthandPropertyAssignment(property)) {
        const origin = callerShapedOrigin(property.name, scope);
        if (origin) flows.push({ node: property, value: property.name, origin, kind: "value", key: property.name.text });
        continue;
      }
      if (!ts.isPropertyAssignment(property)) continue;
      const key =
        ts.isIdentifier(property.name) || ts.isStringLiteralLike(property.name) ? property.name.text : "";
      const value = property.initializer;
      if (ts.isObjectLiteralExpression(value) && depth < 3) {
        flows.push(...filterFlows(value, scope, depth + 1));
        continue;
      }
      if (isConstantString(value) || value.kind === ts.SyntaxKind.NullKeyword) continue;
      // `$where` and friends evaluate their argument, so even a string is code.
      if (EVALUATED_OPERATORS.has(key)) {
        const origin = taintOrigin(value, scope);
        if (origin) flows.push({ node: property, value, origin, kind: "value", key, evaluated: true });
        continue;
      }
      const origin = callerShapedOrigin(value, scope);
      if (origin) flows.push({ node: property, value, origin, kind: "value", key });
    }
    return flows;
  }

  const origin = callerShapedOrigin(resolved, scope) ?? callerShapedOrigin(argument, scope);
  if (origin) flows.push({ node: argument, value: argument, origin, kind: "whole" });
  return flows;
}

/** Does this file talk to MongoDB at all? */
function usesMongo(context: RuleContext): boolean {
  if (importsModule(context, /(mongodb|mongoose|mongo)/i)) return true;
  const text = context.file.text;
  if (/\.collection\(|getCollection\(|\bdb\.collection\b|\bObjectId\(/.test(text)) return true;
  return /\$(set|unset|inc|push|pull|addToSet|ne|gt|gte|lt|lte|in|nin|or|and|nor|not|where|regex|exists|expr|elemMatch)\b/.test(
    text
  );
}

/**
 * Route-level input validation.
 *
 * Fastify, and every framework that copied it, validates the body before the
 * handler runs when the route declares a schema. Two handlers can be identical
 * at the sink and differ only in whether their registration passed one — so the
 * registration is where the answer is, and a file-wide search for the word
 * `schema` would find the *other* route's schema and stay quiet on this one.
 */
function routeValidatesInput(node: ts.Node, source: ts.SourceFile): boolean {
  let current: ts.Node | undefined = node.parent;
  while (current) {
    if (ts.isCallExpression(current)) {
      const tail = calleeTail(current).toLowerCase();
      if (REGISTRATION_METHODS.has(tail) || tail === "route") {
        for (const argument of current.arguments) {
          if (!ts.isObjectLiteralExpression(argument)) continue;
          for (const property of argument.properties) {
            if (!ts.isPropertyAssignment(property) && !ts.isShorthandPropertyAssignment(property)) continue;
            const key = ts.isIdentifier(property.name) ? property.name.text : "";
            if (key !== "schema") continue;
            if (ts.isShorthandPropertyAssignment(property)) return true;
            const value = (property as ts.PropertyAssignment).initializer;
            if (declaresInputSchema(value, source)) return true;
          }
        }
      }
    }
    current = current.parent;
  }
  return false;
}

/** A schema that constrains the *input*, not only the response shape. */
function declaresInputSchema(value: ts.Expression, source: ts.SourceFile, depth = 0): boolean {
  if (ts.isIdentifier(value) && depth < 3) {
    const initializer = declarationsIn(source).get(value.text);
    return initializer ? declaresInputSchema(initializer, source, depth + 1) : true;
  }
  if (!ts.isObjectLiteralExpression(value)) return true;
  return value.properties.some((property) => {
    const name =
      (ts.isPropertyAssignment(property) || ts.isShorthandPropertyAssignment(property)) && ts.isIdentifier(property.name)
        ? property.name.text
        : "";
    return name === "body" || name === "params" || name === "querystring" || name === "query" || name === "headers";
  });
}

export const nosqlInjection: Rule = {
  id: "nosql-injection",
  category: "nosql_injection",
  describes: "a caller-supplied object reaching a document-database filter",
  run(context: RuleContext) {
    if (!usesMongo(context)) return;

    for (const call of collect(context.file.source, ts.isCallExpression)) {
      const tail = calleeTail(call);
      const positions = MONGO_QUERY_METHODS.get(tail);
      if (!positions) continue;
      if (!ts.isPropertyAccessExpression(call.expression)) continue;

      for (const position of positions) {
        const argument = call.arguments[position];
        if (!argument) continue;
        // `list.find(entry => ...)` is Array.prototype.find, not a query.
        if (ts.isArrowFunction(argument) || ts.isFunctionExpression(argument)) continue;
        if (isConstantString(argument)) continue;

        const scope = innermostScope(context, call);
        if (!scope) continue;
        const isUpdateDocument = position === 1 && tail !== "distinct";
        const flows = filterFlows(argument, scope).filter((flow) =>
          // In an update document a fixed operator with caller-supplied values is
          // mass assignment, not injection; only a wholly caller-controlled
          // document lets the caller choose the operator.
          isUpdateDocument ? flow.kind === "whole" : true
        );
        if (flows.length === 0) continue;
        if (routeValidatesInput(call, context.file.source)) continue;

        // A `typeof x !== "string"` check that stops the handler makes the value a
        // scalar as surely as a coercion does.
        const reportable = flows.filter((flow) => !scalarGuarded(scope, rootOf(flow.value) ?? flow.key ?? null));
        const flow = reportable[0];
        if (!flow) continue;

        const receiver = expressionName(call.expression.expression);
        const sink = `${receiver}.${tail}()`;
        const keys = reportable.map((entry) => entry.key).filter(Boolean);
        const where = flow.evaluated
          ? `the \`${flow.key}\` operator of the filter, whose value the server evaluates`
          : flow.kind === "spread"
            ? "spread whole into the filter object, so its keys become part of the query"
            : flow.kind === "whole"
              ? `used as the entire ${isUpdateDocument ? "update document" : "filter"}`
              : `used as the value of ${keys.length > 1 ? `the ${keys.map((key) => `\`${key}\``).join(" and ")} fields` : `the \`${flow.key}\` field`}`;

        context.report({
          ruleId: "nosql-injection",
          category: "nosql_injection",
          title: `Caller-supplied object reaches the ${isUpdateDocument ? "update document" : "filter"} of ${sink}`,
          severity: flow.evaluated ? "critical" : "high",
          verification: "strong_evidence",
          summary: `A value derived from ${flow.origin} is ${where}. Nothing between the request and the query coerces it to a scalar or rebuilds it from known keys, so the caller can send an object where a value is expected — \`{"$ne": null}\`, \`{"$gt": ""}\`, or \`{"$where": "..."}\` — and change what the query means rather than what it matches.${
            flow.kind === "spread"
              ? " Because the spread is merged into the same object as the scoping keys, a caller-chosen key can also overwrite the conditions that limit the query to their own tenant."
              : ""
          }`,
          impact: flow.evaluated
            ? "The operator's value is executed by the database server, so this is code execution inside the datastore as well as unrestricted read access."
            : "An attacker turns an exact-match lookup into a match-anything query: authentication and token checks that depend on the filter are bypassed without knowing the secret, and records belonging to other tenants are returned.",
          remediation:
            "Never pass a caller-supplied object into a query. Coerce every value to the scalar type the field holds (`String(value)`, `Number(value)`, `new ObjectId(value)`), reject anything that is not that type, and build the filter key by key from an allowlist of the fields the endpoint supports. Where the framework offers it, declare a request schema on the route so a non-scalar is rejected before the handler runs.",
          verificationPlan:
            `Send the request with this field as an object — for example \`{"${flow.key ?? "field"}": {"$ne": null}}\` — and confirm the endpoint refuses it rather than returning a record. Then send \`{"$where": "sleep(2000)"}\` and confirm the response time does not change.`,
          taxonomy: ["CWE-943", "CWE-89", "OWASP-A03"],
          location: locationOf(context, flow.node),
          ...withRoute(context, call),
          evidence: [
            sourceEvidence(context, flow.node, `Caller-controlled data is placed in the query given to ${sink}.`),
            taintEvidence(flow.origin, sink)
          ],
          reasoning: `Taint from ${flow.origin} reaches argument ${position} of ${sink} as ${flow.kind}; no scalar coercion, type guard, or route input schema applies to it.`
        });
        break;
      }
    }
  }
};

/* ------------------------------------------------------------------ *
 * unsafe_deserialization
 * ------------------------------------------------------------------ */

/** Schemas that restrict a YAML load to plain data. */
const SAFE_YAML_SCHEMA = /JSON_SCHEMA|CORE_SCHEMA|FAILSAFE_SCHEMA/;

interface DeserializerHit {
  label: string;
  severity: "critical" | "high";
  detail: string;
}

function deserializerFor(context: RuleContext, call: ts.CallExpression): DeserializerHit | null {
  const name = calleeName(call);
  const tail = calleeTail(call);
  const receiver = ts.isPropertyAccessExpression(call.expression)
    ? expressionName(call.expression.expression)
    : "";

  if (tail === "unserialize" || tail === "unserializeSync") {
    const php = importsModule(context, /php-?un?serialize|serialize-php/i);
    return {
      label: name,
      severity: "critical",
      detail: php
        ? "PHP serialization formats encode object types, so parsing reconstructs whatever class the payload names."
        : "node-serialize's format encodes functions, and `unserialize` invokes them as it rebuilds the object."
    };
  }
  if (tail === "unsafeLoad") {
    return { label: name, severity: "critical", detail: "The unsafe schema constructs any type the document tags." };
  }
  if ((tail === "load" || tail === "loadAll") && (/yaml/i.test(receiver) || (receiver === "" && importsModule(context, /^js-?yaml|^yaml/i)))) {
    const options = call.arguments
      .slice(1)
      .map((argument) => argument.getText(context.file.source))
      .join(" ");
    if (SAFE_YAML_SCHEMA.test(options)) return null;
    return {
      label: name,
      severity: "high",
      detail: "With no schema argument the loader accepts every tag the default schema knows, including type tags that construct objects."
    };
  }
  if (tail === "deserialize" && /^(v8|node:v8)$/i.test(receiver)) {
    return {
      label: name,
      severity: "high",
      detail: "The V8 serialization format is a memory format, not a wire format; a malformed or hostile buffer is not handled safely."
    };
  }
  // `JSON.parse(text, reviver)` where the reviver evaluates what it is given.
  if (name === "JSON.parse" && call.arguments.length > 1) {
    const reviver = call.arguments[1]!;
    if (/\beval\s*\(|new\s+Function|vm\./.test(reviver.getText(context.file.source))) {
      return {
        label: "JSON.parse with an evaluating reviver",
        severity: "critical",
        detail: "The reviver compiles values out of the document, so the document is code."
      };
    }
  }
  return null;
}

export const unsafeDeserializationParsers: Rule = {
  id: "unsafe-deserialization-parser",
  category: "unsafe_deserialization",
  describes: "caller-controlled data parsed by a format that reconstructs types",
  run(context: RuleContext) {
    for (const call of collect(context.file.source, ts.isCallExpression)) {
      const hit = deserializerFor(context, call);
      if (!hit) continue;

      const payload = call.arguments[0];
      if (!payload) continue;
      const origin = taintAt(context, call, payload);
      if (!origin) continue;

      context.report({
        ruleId: "unsafe-deserialization-parser",
        category: "unsafe_deserialization",
        title: `Caller-controlled data is deserialized by ${hit.label}`,
        severity: hit.severity,
        verification: "strong_evidence",
        summary: `A value derived from ${origin} is passed to ${hit.label}. ${hit.detail} The decision about what to construct is therefore taken from the payload, before any of this handler's own validation runs.`,
        impact:
          hit.severity === "critical"
            ? "A crafted payload runs code in the application process during parsing — the attacker does not need the rest of the handler to behave in any particular way."
            : "A crafted payload constructs types the application never intended to build, which ranges from denial of service to code execution depending on what those types do when they are created.",
        remediation:
          "Parse with a format that only carries data: `JSON.parse` for JSON, or a YAML loader pinned to a restricted schema. Then validate the parsed value field by field against the shape the handler expects — check each type, length, and range, and copy only the fields you accept onto a fresh object — so nothing the payload declares can influence which types exist.",
        verificationPlan:
          "Post a payload containing the format's type or function tag (for node-serialize, a `$$ND_FUNC$$` value; for YAML, a `!!js/function` tag) with an observable side effect such as a request to a host you control, and confirm the request is rejected and no callback fires.",
        taxonomy: ["CWE-502", "CWE-913", "OWASP-A08"],
        location: locationOf(context, call),
        ...withRoute(context, call),
        evidence: [
          sourceEvidence(context, call, `${hit.label} parses data that came from the request.`),
          taintEvidence(origin, `${hit.label}()`)
        ],
        reasoning: `Taint from ${origin} reaches the payload argument of ${hit.label}, and no restricted schema or post-parse shape validation intervenes.`
      });
    }
  }
};

/* ------------------------------------------------------------------ *
 * prototype_pollution
 * ------------------------------------------------------------------ */

/** Keys that reach the prototype chain when written by a merge. */
const RESERVED_KEY = /__proto__|constructor|prototype/;

/** Deep merges shipped by libraries, where the recursion is not in this file. */
const LIBRARY_DEEP_MERGE = new Set(["merge", "mergeWith", "defaultsDeep", "deepmerge", "mergeDeep", "extend", "set", "setWith"]);

/** Receivers that are a merge library rather than a domain object. */
const MERGE_LIBRARY_RECEIVER = /^(_|lodash|deepmerge|merge|mergeDeep|objectPath|dotProp|deepExtend|defaultsDeep)$/;

const MERGE_LIBRARY_MODULE = /(lodash|deepmerge|merge-deep|deep-extend|object-path|dot-prop|assign-deep|defaults-deep|merge-options|ramda)/i;

interface MergeFunction {
  node: ts.Node;
  name: string;
  guarded: boolean;
}

/**
 * A locally written recursive merge or deep assignment.
 *
 * This is the shape prototype pollution actually takes in application code: not
 * a call to lodash, but a twelve-line `applyPatch` that walks the keys of a
 * request body and writes them onto a target. A rule that only knows library
 * names cannot see it, and the guarded version of the same function — the one
 * that skips reserved keys — is only a line or two different.
 */
function mergeFunctionsIn(context: RuleContext): MergeFunction[] {
  const found: MergeFunction[] = [];
  const source = context.file.source;

  for (const fn of functionsIn(source)) {
    if (ts.isSourceFile(fn)) continue;
    const declaration = fn as ts.FunctionLikeDeclaration;
    const body = declaration.body;
    if (!body) continue;
    const name = functionName(fn);
    if (!name) continue;
    const parameters = declaration.parameters
      .filter((parameter) => ts.isIdentifier(parameter.name))
      .map((parameter) => (parameter.name as ts.Identifier).text);
    if (parameters.length < 2) continue;

    // A dynamic write onto one of the parameters.
    let dynamicWrite = false;
    // Iteration over the keys of another parameter, or a split path.
    let walksKeys = false;
    let recurses = false;

    walk(body, (node) => {
      if (
        ts.isBinaryExpression(node) &&
        node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
        ts.isElementAccessExpression(node.left) &&
        !ts.isStringLiteralLike(node.left.argumentExpression)
      ) {
        const target = rootOf(node.left);
        if (target && parameters.includes(target)) dynamicWrite = true;
      }
      if (ts.isCallExpression(node)) {
        const callName = calleeName(node);
        if (/^Object\.(keys|entries|getOwnPropertyNames|assign)$/.test(callName)) {
          const first = node.arguments[0];
          const target = first ? rootOf(first) : null;
          if (target && parameters.includes(target)) walksKeys = true;
        }
        if (calleeTail(node) === "split") {
          const target = rootOf(node.expression);
          if (target && parameters.includes(target)) walksKeys = true;
        }
        if (ts.isIdentifier(node.expression) && node.expression.text === name) recurses = true;
      }
      if (ts.isForInStatement(node)) {
        const target = rootOf(node.expression);
        if (target && parameters.includes(target)) walksKeys = true;
      }
      if (ts.isForOfStatement(node)) {
        const target = rootOf(node.expression);
        if (target && parameters.includes(target)) walksKeys = true;
      }
    });

    if (!dynamicWrite || !walksKeys || !recurses) continue;

    found.push({ node: fn, name, guarded: mergeIsGuarded(context, body) });
  }

  return found;
}

/** Does the merge refuse the keys that reach the prototype chain? */
function mergeIsGuarded(context: RuleContext, body: ts.Node): boolean {
  const text = body.getText(context.file.source);
  if (RESERVED_KEY.test(text)) return true;
  if (/Object\.create\(\s*null\s*\)|Object\.hasOwn|hasOwnProperty|Object\.freeze|new Map\(|instanceof Map/.test(text)) {
    return true;
  }
  // A reserved-key list held in a module constant: `if (RESERVED.has(key)) continue`.
  const declarations = declarationsIn(context.file.source);
  let guarded = false;
  walk(body, (node) => {
    if (guarded || !ts.isIdentifier(node)) return;
    const initializer = declarations.get(node.text);
    if (initializer && RESERVED_KEY.test(initializer.getText(context.file.source))) guarded = true;
  });
  return guarded;
}

export const prototypePollutingMerge: Rule = {
  id: "prototype-pollution-deep-merge",
  category: "prototype_pollution",
  describes: "a recursive merge of caller data with no reserved-key guard",
  run(context: RuleContext) {
    const merges = mergeFunctionsIn(context).filter((merge) => !merge.guarded);
    const byName = new Map(merges.map((merge) => [merge.name, merge]));

    for (const call of collect(context.file.source, ts.isCallExpression)) {
      const name = calleeName(call);
      const tail = calleeTail(call);
      const local = ts.isIdentifier(call.expression) ? byName.get(call.expression.text) : undefined;

      const receiver = ts.isPropertyAccessExpression(call.expression)
        ? expressionName(call.expression.expression)
        : "";
      const isLibraryMerge =
        LIBRARY_DEEP_MERGE.has(tail) &&
        (MERGE_LIBRARY_RECEIVER.test(receiver) ||
          (receiver === "" && ts.isIdentifier(call.expression) && importsModule(context, MERGE_LIBRARY_MODULE)));

      if (!local && !isLibraryMerge) continue;

      // A null-prototype target is the one target a merge cannot pollute. A fresh
      // object literal is not: `{}.__proto__` is still Object.prototype, so a
      // recursive merge into a fresh object reaches it on the first key.
      const target = call.arguments[0];
      if (target && /Object\.create\(\s*null\s*\)/.test(target.getText(context.file.source))) continue;

      const source = call.arguments.slice(1);
      const origin = source.map((argument) => taintAt(context, call, argument)).find(Boolean);
      if (!origin) continue;

      const site = local ? local.node : call;
      const label = local ? `\`${local.name}\`` : `${name}()`;

      context.report({
        ruleId: "prototype-pollution-deep-merge",
        category: "prototype_pollution",
        title: `${local ? `The recursive merge ${label}` : `The deep merge ${label}`} copies caller-controlled keys onto an existing object`,
        severity: "high",
        verification: "strong_evidence",
        summary: `${label} walks the keys of a value derived from ${origin} and assigns them onto the target object, and nothing in it refuses \`__proto__\`, \`constructor\`, or \`prototype\`. A request body containing one of those keys therefore writes onto the prototype chain instead of onto the object.`,
        impact:
          "A polluted prototype changes the behaviour of every object in the process: default-value checks start returning attacker-chosen values, authorisation flags appear on objects that never had them, and libraries that read configuration off plain objects can be pushed into command execution. The effect outlives the request that caused it.",
        remediation:
          "Skip `__proto__`, `constructor` and `prototype` explicitly at the top of the key loop, build intermediate nodes with `Object.create(null)`, and test existing keys with `Object.hasOwn` rather than plain property access. Better still, validate the patch against a schema of the fields the endpoint accepts and copy those fields by name instead of merging an arbitrary tree.",
        verificationPlan:
          "Send a patch body of `{\"__proto__\": {\"polluted\": \"yes\"}}`, then request any other endpoint and confirm that a fresh object does not report `polluted` — for example that a response field that should be absent is still absent. Repeat with `{\"constructor\": {\"prototype\": {\"polluted\": \"yes\"}}}`.",
        taxonomy: ["CWE-1321", "CWE-915", "OWASP-A08"],
        location: locationOf(context, site),
        ...withRoute(context, call),
        evidence: [
          sourceEvidence(context, site, `${label} assigns caller-controlled keys onto its target with no reserved-key check.`),
          sourceEvidence(context, call, `Caller-controlled data derived from ${origin} is passed to ${label} here.`),
          taintEvidence(origin, local ? `${local.name}()` : `${name}()`)
        ],
        reasoning: local
          ? `\`${local.name}\` iterates the keys of a parameter, writes them to a dynamic index on another parameter, and recurses; the body contains no reserved-key guard, no Object.create(null), and no hasOwn check. It is called with taint from ${origin}.`
          : `${name}() is a deep merge from a merge library, its target is not a fresh literal, and taint from ${origin} reaches its source argument.`
      });
      if (local) byName.delete(local.name);
    }
  }
};

/* ------------------------------------------------------------------ *
 * code_injection
 * ------------------------------------------------------------------ */

/** Calls that compile or run their argument as source. */
const INTERPRETER_CALLS = new Set([
  "eval",
  "Function",
  "vm.runInNewContext",
  "vm.runInThisContext",
  "vm.runInContext",
  "vm.compileFunction",
  "vm.Script",
  "vm.SourceTextModule",
  "runInNewContext",
  "runInThisContext",
  "runInContext",
  "compileFunction"
]);

/** Constructors that compile source. */
const INTERPRETER_CONSTRUCTORS = /^(Function|vm\.Script|vm\.SourceTextModule|Script|SourceTextModule|AsyncFunction|GeneratorFunction)$/;

export const interpreterCodeInjection: Rule = {
  id: "code-injection-interpreter",
  category: "code_injection",
  describes: "caller-controlled data compiled or executed as code",
  run(context: RuleContext) {
    const vmImported = importsModule(context, /^(node:)?vm$/);

    for (const call of collect(context.file.source, ts.isCallExpression)) {
      const name = calleeName(call);
      const tail = calleeTail(call);

      // `require(userInput)` and `import(userInput)` load whatever module the
      // caller names, which is the same primitive with an extra step.
      if (name === "require" || call.expression.kind === ts.SyntaxKind.ImportKeyword) {
        const specifier = call.arguments[0];
        if (!specifier || isConstantString(specifier)) continue;
        const origin = taintAt(context, call, specifier);
        if (!origin) continue;
        reportCode(context, call, name === "require" ? "require()" : "import()", origin, "module");
        continue;
      }

      // `setTimeout("code", 0)` is `eval` with a delay.
      if ((name === "setTimeout" || name === "setInterval") && call.arguments[0]) {
        const first = call.arguments[0]!;
        if (ts.isArrowFunction(first) || ts.isFunctionExpression(first) || ts.isIdentifier(first)) continue;
        if (!isStringLike(first) && !ts.isBinaryExpression(first)) continue;
        const origin = taintAt(context, call, first);
        if (!origin) continue;
        reportCode(context, call, `${name}() with a string body`, origin, "source");
        continue;
      }

      const isInterpreter =
        INTERPRETER_CALLS.has(name) ||
        (INTERPRETER_CALLS.has(tail) && (vmImported || /vm|script|sandbox|interpreter/i.test(name)));
      if (!isInterpreter) continue;

      const tainted = call.arguments
        .map((argument) => ({ argument, origin: taintAt(context, call, argument) }))
        .find((entry) => entry.origin);
      if (!tainted?.origin) continue;
      reportCode(context, call, `${name}()`, tainted.origin, "source");
    }

    for (const expression of collect(context.file.source, ts.isNewExpression)) {
      const name = expressionName(expression.expression);
      if (!INTERPRETER_CONSTRUCTORS.test(name)) continue;
      const argumentList = expression.arguments ?? ts.factory.createNodeArray<ts.Expression>();
      // A hand-rolled template renderer is reported as template injection, so the
      // same line is never reported twice under two classes.
      if (
        name === "Function" &&
        argumentList.some((argument) => TEMPLATE_DELIMITERS.test(argument.getText(context.file.source)))
      ) {
        continue;
      }
      const tainted = argumentList
        .map((argument) => ({ argument, origin: taintAt(context, expression, argument) }))
        .find((entry) => entry.origin);
      if (!tainted?.origin) continue;
      reportCode(context, expression, `new ${name}()`, tainted.origin, "source");
    }
  }
};

function reportCode(
  context: RuleContext,
  node: ts.Node,
  sink: string,
  origin: string,
  kind: "source" | "module"
): void {
  context.report({
    ruleId: "code-injection-interpreter",
    category: "code_injection",
    title:
      kind === "module"
        ? `Caller-controlled data selects the module loaded by ${sink}`
        : `Caller-controlled data is compiled and executed by ${sink}`,
    severity: "critical",
    verification: "strong_evidence",
    summary:
      kind === "module"
        ? `A value derived from ${origin} is used as the module specifier for ${sink}. The caller therefore chooses which file the process loads and executes, including paths that traverse out of the intended directory.`
        : `A value derived from ${origin} is passed to ${sink}, which compiles it and runs it in this process. The caller supplies the program, not the data — and a compile step separated from the run step is the same defect: whatever is compiled here will be executed.`,
    impact:
      "This is arbitrary code execution in the application process: the attacker gets the database credentials, the secrets in the environment, the filesystem, and the network position of the service. A `vm` context is not a security boundary and does not change that.",
    remediation:
      kind === "module"
        ? "Load modules from a fixed map from an accepted key to a static import. Never build a specifier from request data."
        : "Remove the dynamic compilation. Express the feature as data the application interprets: parse the expression into an operator tree with an allowlist of fields and operators and evaluate it yourself, or offer a fixed catalogue of computations the request selects by key. If arbitrary user code genuinely has to run, it belongs in an isolated process with no credentials, no filesystem, and a hard timeout — not in `vm`.",
    verificationPlan:
      kind === "module"
        ? "Send a specifier that traverses the filesystem or names an unexpected package and confirm the request is refused before any module is loaded."
        : "Send a payload with an observable side effect that no legitimate expression would have — an outbound request to a host you control, or a two-second sleep — and confirm the response is unaffected and no request arrives.",
    taxonomy: kind === "module" ? ["CWE-94", "CWE-98", "OWASP-A03"] : ["CWE-94", "CWE-95", "OWASP-A03"],
    location: locationOf(context, node),
    ...withRoute(context, node),
    evidence: [
      sourceEvidence(context, node, `${sink} receives caller-controlled input.`),
      taintEvidence(origin, sink)
    ],
    reasoning: `Taint from ${origin} reaches ${sink}; the argument is not a constant and no allowlist or coercion applies to it.`
  });
}

/** Every rule in this file, in the order a reader would want them applied. */
export const parsingRules: readonly Rule[] = Object.freeze([
  templateInjection,
  xmlExternalEntity,
  nosqlInjection,
  unsafeDeserializationParsers,
  prototypePollutingMerge,
  interpreterCodeInjection
]);

