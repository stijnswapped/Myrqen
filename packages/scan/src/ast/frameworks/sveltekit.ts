import ts from "typescript";
import { importsFrom, type EntryPoint, type FrameworkAdapter, type TaintSeed } from "../entrypoints.js";
import { lineOf, type ParsedFile } from "../parse.js";

/**
 * SvelteKit 2 server routes, and the Remix / React Router v7 route modules that
 * share their shape.
 *
 * Neither framework registers a route with a call, which is precisely why a
 * scanner built around `app.get("/x", handler)` sees nothing here. The address
 * lives in the directory tree and the handler is an ordinary named export, so the
 * only way to recover it is to read the file's own path and its export list. Miss
 * that and a `+server.ts` full of caller-driven file reads has no entry point, no
 * request parameter, no taint, and therefore no findings at all.
 *
 * The second half of the job is naming the caller-controlled bindings. A SvelteKit
 * handler receives one RequestEvent, almost always destructured, and the keys of
 * that bag are not equally trustworthy: `params` and `url` are whatever the caller
 * typed, while `locals` is whatever a server hook decided to attach. A model that
 * cannot tell them apart either invents flows out of session data or loses the real
 * ones, so the distinction is declared here rather than guessed downstream.
 */

/**
 * Exports SvelteKit routes to in a `+server` module.
 *
 * `fallback` answers every method the module did not export, so it has no single
 * verb of its own; reporting it as ANY is the honest reading and keeps a reader
 * from believing a specific method was checked.
 */
const SERVER_METHOD_EXPORTS = new Map<string, string>([
  ["GET", "GET"],
  ["POST", "POST"],
  ["PUT", "PUT"],
  ["PATCH", "PATCH"],
  ["DELETE", "DELETE"],
  ["OPTIONS", "OPTIONS"],
  ["HEAD", "HEAD"],
  ["fallback", "ANY"]
]);

/**
 * RequestEvent keys that hold data the caller chose, and the wording used verbatim
 * in evidence.
 *
 * The list is deliberately short. `platform`, `setHeaders`, `fetch`, `depends`,
 * `parent`, `route` and `isDataRequest` are all supplied by the framework or the
 * adapter, and seeding any of them would manufacture a flow the caller never
 * influenced — across every data-flow rule in the engine at once.
 */
const EVENT_SEEDS = new Map<string, string>([
  ["params", "event.params (caller-controlled route parameters)"],
  ["url", "event.url (caller-controlled request URL)"],
  ["request", "event.request (inbound request)"],
  ["cookies", "event.cookies (caller-controlled cookies)"]
]);

/**
 * `locals` is what the `handle` hook attached — a resolved session, a tenant, a
 * database handle. It reads like request data and is not, so it is named as
 * trusted instead of being left for the generic parameter model to guess at.
 */
const SERVER_ATTACHED_EVENT_KEYS = new Set(["locals"]);

/** The three server modules SvelteKit will execute for a request. */
const ROUTE_FILE_NAME = /^\+(server|page\.server|layout\.server)\.[cm]?[jt]s$/;

type RouteFileKind = "server" | "page" | "layout";

interface SvelteKitRouteFile {
  /** The URL path, spelled the way the directories spell it. */
  route: string;
  kind: RouteFileKind;
}

/**
 * The route a SvelteKit server module answers on, read from its own location.
 *
 * SvelteKit's bracket syntax is kept exactly as the directory spells it —
 * `[name]`, `[...rest]`, `[[optional]]`. Rewriting those into `:name` would
 * produce a path no SvelteKit developer would search for and that matches nothing
 * anybody wrote down.
 */
export function sveltekitRouteFile(relativePath: string): SvelteKitRouteFile | null {
  const segments = relativePath.split(/[\\/]/);
  const fileName = segments.pop();
  if (!fileName) return null;

  const named = ROUTE_FILE_NAME.exec(fileName);
  if (!named) return null;

  // The first `routes` segment is the routing root. Taking the first rather than
  // the last keeps a monorepo prefix (`apps/web/src/routes/...`) out of the URL
  // while still allowing a page that is itself called `routes` further down.
  const routesIndex = segments.indexOf("routes");
  if (routesIndex === -1) return null;

  const directories = segments
    .slice(routesIndex + 1)
    // A group exists to share a layout, not to add a segment: `(app)/dashboard`
    // is served at `/dashboard`.
    .filter((segment) => !(segment.startsWith("(") && segment.endsWith(")")));

  const kind: RouteFileKind = named[1] === "server" ? "server" : named[1] === "page.server" ? "page" : "layout";
  return { route: directories.length === 0 ? "/" : `/${directories.join("/")}`, kind };
}

/** A named export and the function it resolves to, whichever way it was written. */
interface ExportedBinding {
  name: string;
  /** The statement to blame in the report, so the line points at the export. */
  declaration: ts.Node;
  /** The value exported, before any type wrapper is peeled off. */
  value: ts.Expression | undefined;
  /** The function whose body runs, when the export is one. */
  fn: ts.Node | undefined;
}

/** The function-like node behind an expression, seeing through type wrappers. */
function functionBehind(node: ts.Node | undefined): ts.Node | undefined {
  if (!node) return undefined;
  if (ts.isArrowFunction(node) || ts.isFunctionExpression(node) || ts.isFunctionDeclaration(node)) return node;
  if (ts.isMethodDeclaration(node)) return node;
  // `export const GET: RequestHandler = (async (event) => {}) satisfies X` is all
  // the same handler; a model that stops at the first wrapper loses the body.
  if (ts.isParenthesizedExpression(node) || ts.isAsExpression(node) || ts.isSatisfiesExpression(node)) {
    return functionBehind(node.expression);
  }
  if (ts.isTypeAssertionExpression(node)) return functionBehind(node.expression);
  return undefined;
}

/** The object literal behind an expression, seeing through the same wrappers. */
function objectBehind(node: ts.Node | undefined): ts.ObjectLiteralExpression | undefined {
  if (!node) return undefined;
  if (ts.isObjectLiteralExpression(node)) return node;
  if (ts.isParenthesizedExpression(node) || ts.isAsExpression(node) || ts.isSatisfiesExpression(node)) {
    return objectBehind(node.expression);
  }
  if (ts.isTypeAssertionExpression(node)) return objectBehind(node.expression);
  return undefined;
}

function hasExportModifier(node: ts.Node): boolean {
  return (
    ts.canHaveModifiers(node) &&
    (ts.getModifiers(node) ?? []).some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword)
  );
}

/** A top-level `function name(){}` or `const name = ...` declared in this file. */
function localBinding(file: ParsedFile, name: string): ExportedBinding | undefined {
  for (const statement of file.source.statements) {
    if (ts.isFunctionDeclaration(statement) && statement.name?.text === name) {
      return { name, declaration: statement, value: undefined, fn: statement };
    }
    if (!ts.isVariableStatement(statement)) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (!ts.isIdentifier(declaration.name) || declaration.name.text !== name) continue;
      return {
        name,
        declaration: statement,
        value: declaration.initializer,
        fn: functionBehind(declaration.initializer)
      };
    }
  }
  return undefined;
}

/**
 * Every value this module exports under a name.
 *
 * Four spellings reach the same place: a declared function, a const initialiser,
 * a re-export of a local name (`export { handler as POST }`), and the CommonJS
 * `exports.POST = ...` that a plain `.js` route module still uses. Recognising
 * only the first would leave the others without an entry point, which is the same
 * as leaving them unscanned.
 */
function exportedBindings(file: ParsedFile): ExportedBinding[] {
  const found: ExportedBinding[] = [];

  for (const statement of file.source.statements) {
    if (ts.isFunctionDeclaration(statement) && statement.name && hasExportModifier(statement)) {
      found.push({ name: statement.name.text, declaration: statement, value: undefined, fn: statement });
      continue;
    }

    if (ts.isVariableStatement(statement) && hasExportModifier(statement)) {
      for (const declaration of statement.declarationList.declarations) {
        if (!ts.isIdentifier(declaration.name)) continue;
        found.push({
          name: declaration.name.text,
          declaration: statement,
          value: declaration.initializer,
          fn: functionBehind(declaration.initializer)
        });
      }
      continue;
    }

    if (ts.isExportDeclaration(statement) && !statement.moduleSpecifier && statement.exportClause) {
      // `export { load }` and `export { handler as POST }`. A re-export that names
      // another module cannot be resolved from this file, so it is left alone.
      if (!ts.isNamedExports(statement.exportClause)) continue;
      for (const element of statement.exportClause.elements) {
        const local = (element.propertyName ?? element.name).text;
        const resolved = localBinding(file, local);
        found.push({
          name: element.name.text,
          declaration: resolved?.declaration ?? statement,
          value: resolved?.value,
          fn: resolved?.fn
        });
      }
      continue;
    }

    if (!ts.isExpressionStatement(statement)) continue;
    const assignment = statement.expression;
    if (!ts.isBinaryExpression(assignment) || assignment.operatorToken.kind !== ts.SyntaxKind.EqualsToken) continue;

    // `exports.POST = handler`
    if (ts.isPropertyAccessExpression(assignment.left) && ts.isIdentifier(assignment.left.expression)) {
      const receiver = assignment.left.expression.text;
      if (receiver === "exports") {
        found.push({
          name: assignment.left.name.text,
          declaration: statement,
          value: assignment.right,
          fn: functionBehind(assignment.right)
        });
      }
      continue;
    }

    // `module.exports = { POST: handler }`
    const target = assignment.left;
    if (!ts.isPropertyAccessExpression(target)) continue;
    if (target.name.text !== "exports") continue;
    if (!ts.isIdentifier(target.expression) || target.expression.text !== "module") continue;
    const literal = objectBehind(assignment.right);
    if (!literal) continue;
    for (const property of literal.properties) {
      const named = propertyBinding(file, property);
      if (named) found.push(named);
    }
  }

  return found;
}

/** One entry of an object literal, resolved to the function it holds. */
function propertyBinding(file: ParsedFile, property: ts.ObjectLiteralElementLike): ExportedBinding | undefined {
  if (ts.isPropertyAssignment(property)) {
    const key = propertyKey(property.name);
    if (!key) return undefined;
    return {
      name: key,
      declaration: property,
      value: property.initializer,
      fn: functionBehind(property.initializer)
    };
  }
  if (ts.isMethodDeclaration(property)) {
    const key = propertyKey(property.name);
    if (!key) return undefined;
    return { name: key, declaration: property, value: undefined, fn: property };
  }
  if (ts.isShorthandPropertyAssignment(property)) {
    // `export const actions = { login }` puts the handler somewhere above; without
    // resolving it the action has no body and every flow inside it is invisible.
    const resolved = localBinding(file, property.name.text);
    return {
      name: property.name.text,
      declaration: property,
      value: resolved?.value,
      fn: resolved?.fn
    };
  }
  return undefined;
}

function propertyKey(name: ts.PropertyName): string | null {
  if (ts.isIdentifier(name)) return name.text;
  if (ts.isStringLiteralLike(name)) return name.text;
  return null;
}

interface HandlerBindings {
  seeds: TaintSeed[];
  trusted: string[];
}

/**
 * The caller-controlled bindings a handler destructured out of its event bag.
 *
 * Only the keys in `EVENT_SEEDS` become seeds, and the name recorded is the bound
 * name rather than the key, because `{ params: p }` puts the route parameters in
 * `p` and a seed on `params` would mark a binding that does not exist.
 */
function bindingsOf(fn: ts.Node | undefined, seedOrigins: Map<string, string>, serverAttached: Set<string>): HandlerBindings {
  const parameter = (fn as ts.FunctionLikeDeclaration | undefined)?.parameters?.[0];
  if (!parameter) return { seeds: [], trusted: [] };

  if (ts.isIdentifier(parameter.name)) {
    // The whole bag is held under one name. `locals` is reachable through it, but
    // the generic model already knows that a server-attached property is not
    // caller data, so declaring trusted parameters here would suppress the real
    // request data on the same object.
    return { seeds: [{ name: parameter.name.text, origin: "event (inbound request)" }], trusted: [] };
  }

  if (!ts.isObjectBindingPattern(parameter.name)) return { seeds: [], trusted: [] };

  const seeds: TaintSeed[] = [];
  const trusted: string[] = [];
  for (const element of parameter.name.elements) {
    // `...rest` carries whichever keys were not named above it. Which ones those
    // are cannot be known here, and a guess would seed a binding that may hold
    // nothing but `platform`.
    if (element.dotDotDotToken) continue;
    // A nested pattern binds something *inside* an event key, and whether that
    // inner value is caller data depends on the key. Left alone rather than
    // guessed at.
    if (!ts.isIdentifier(element.name)) continue;

    const key = propertyKey(element.propertyName ?? element.name);
    if (!key) continue;

    const origin = seedOrigins.get(key);
    if (origin) {
      seeds.push({ name: element.name.text, origin });
      continue;
    }
    if (serverAttached.has(key)) trusted.push(element.name.text);
  }
  return { seeds, trusted };
}

function entryPoint(
  framework: string,
  kind: EntryPoint["kind"],
  method: string,
  path: string,
  line: number,
  fn: ts.Node | undefined,
  bindings: HandlerBindings
): EntryPoint {
  return {
    framework,
    kind,
    method,
    path,
    line,
    ...(fn ? { node: fn } : {}),
    ...(bindings.seeds.length > 0 ? { seeds: bindings.seeds } : {}),
    ...(bindings.trusted.length > 0 ? { trustedParameters: bindings.trusted } : {})
  };
}

function detectSvelteKit(file: ParsedFile): EntryPoint[] {
  const routeFile = sveltekitRouteFile(file.relativePath);
  if (!routeFile) return [];

  const found: EntryPoint[] = [];
  for (const binding of exportedBindings(file)) {
    const bindings = bindingsOf(binding.fn, EVENT_SEEDS, SERVER_ATTACHED_EVENT_KEYS);
    const line = lineOf(file, binding.declaration);

    // `+layout.server.ts` cannot serve a method or a form action; only its `load`
    // runs, and claiming more would put addresses in the report that no request
    // can reach.
    if (routeFile.kind !== "layout") {
      const method = SERVER_METHOD_EXPORTS.get(binding.name);
      if (method && binding.fn) {
        found.push(entryPoint("sveltekit", "http", method, routeFile.route, line, binding.fn, bindings));
        continue;
      }
    }

    if (binding.name === "load" && binding.fn) {
      // A `load` runs on the GET that renders the page, so that is the address a
      // reader would use to reach whatever it does.
      found.push(entryPoint("sveltekit", "http", "GET", routeFile.route, line, binding.fn, bindings));
      continue;
    }

    if (binding.name !== "actions" || routeFile.kind !== "page") continue;
    const actions = objectBehind(binding.value);
    if (!actions) continue;
    for (const property of actions.properties) {
      const action = propertyBinding(file, property);
      if (!action?.fn) continue;
      // A form posts to `?/name`, and the anonymous `default` action to the route
      // itself. The action name is a QUERY STRING, not a path segment, so the
      // endpoint a reader recognises — and the one a report should name — is the
      // page route. Putting `?/login` in the path made every finding in a named
      // action look like it belonged to an endpoint that does not exist.
      const path = routeFile.route;
      found.push(
        entryPoint(
          "sveltekit",
          "action",
          "POST",
          path,
          lineOf(file, action.declaration),
          action.fn,
          bindingsOf(action.fn, EVENT_SEEDS, SERVER_ATTACHED_EVENT_KEYS)
        )
      );
    }
  }

  return found;
}

export const sveltekitAdapter: FrameworkAdapter = {
  id: "sveltekit",
  // The path is the whole pre-filter: a `+server.ts` under a `routes` directory is
  // a SvelteKit endpoint by definition, and nothing else is named that way.
  applies: (file) => sveltekitRouteFile(file.relativePath) !== null,
  detect: detectSvelteKit
};

/* ---------- Remix and React Router v7, which share the export shape ---------- */

const REMIX_MODULES = /@remix-run|react-router/;

/**
 * A `loader` answers the GET that renders or fetches the route. An `action`
 * answers everything else — POST, PUT, PATCH and DELETE all arrive at the same
 * export — and POST is reported because that is what a form sends and what a
 * reader will recognise; the other verbs reach the same code.
 */
const REMIX_EXPORTS = new Map<string, string>([
  ["loader", "GET"],
  ["action", "POST"]
]);

/**
 * The route argument bag is not a RequestEvent, so it gets its own wording, and
 * `context` is the server's own AppLoadContext rather than anything the caller
 * sent.
 */
const REMIX_SEEDS = new Map<string, string>([
  ["params", "params (caller-controlled route parameters)"],
  ["request", "request (inbound request)"]
]);

const REMIX_SERVER_ATTACHED = new Set(["context"]);

/**
 * The URL a Remix route module answers on, derived from its file name.
 *
 * Flat routes encode the path in dots, so `app/routes/notes.$id.tsx` is
 * `/notes/:id`. Several conventions cannot be resolved from the name alone — an
 * optional `(segment)`, an escaped `[.]` literal — and for those this returns null
 * so the caller can say "/" rather than print a path that is wrong. A wrong
 * address is worse than an unknown one: it sends the reader to a file that does
 * not have the defect.
 */
export function remixRoutePath(relativePath: string): string | null {
  const segments = relativePath.split(/[\\/]/);
  const routesIndex = segments.findIndex((segment, index) => segment === "routes" && segments[index - 1] === "app");
  if (routesIndex === -1) return null;

  const tail = segments.slice(routesIndex + 1);
  const last = tail.pop();
  if (!last) return null;

  const withoutExtension = last.replace(/\.[cm]?[jt]sx?$/, "");
  // A folder route puts the module in `<route>/route.tsx`; the file name itself
  // contributes nothing to the URL.
  if (withoutExtension !== "route") tail.push(withoutExtension);

  const parts: string[] = [];
  for (const raw of tail.flatMap((segment) => segment.split("."))) {
    if (raw.length === 0) continue;
    // Escaping and optional segments change the URL in ways the file name alone
    // does not settle.
    if (raw.includes("[") || raw.includes("]")) return null;
    if (raw.startsWith("(") && raw.endsWith(")")) return null;
    // `_index` is the index route and `_auth` is a pathless layout: neither adds a
    // segment. A trailing underscore only opts out of a parent layout.
    if (raw.startsWith("_")) continue;
    const segment = raw.replace(/_$/, "");
    if (segment === "$") {
      parts.push("*");
      continue;
    }
    parts.push(segment.startsWith("$") ? `:${segment.slice(1)}` : segment);
  }

  return parts.length === 0 ? "/" : `/${parts.join("/")}`;
}

function detectRemix(file: ParsedFile): EntryPoint[] {
  // A SvelteKit route file is claimed by the adapter above; claiming it twice
  // would double every finding's address.
  if (sveltekitRouteFile(file.relativePath) !== null) return [];
  // The text pre-filter matched a substring; this is the real check.
  if (!importsFrom(file, REMIX_MODULES)) return [];

  const path = remixRoutePath(file.relativePath) ?? "/";
  const found: EntryPoint[] = [];
  for (const binding of exportedBindings(file)) {
    const method = REMIX_EXPORTS.get(binding.name);
    if (!method || !binding.fn) continue;
    found.push(
      entryPoint(
        "remix",
        "http",
        method,
        path,
        lineOf(file, binding.declaration),
        binding.fn,
        bindingsOf(binding.fn, REMIX_SEEDS, REMIX_SERVER_ATTACHED)
      )
    );
  }
  return found;
}

export const remixAdapter: FrameworkAdapter = {
  id: "remix",
  applies: (file) =>
    REMIX_MODULES.test(file.text) &&
    /\b(loader|action)\b/.test(file.text) &&
    sveltekitRouteFile(file.relativePath) === null,
  detect: detectRemix
};
