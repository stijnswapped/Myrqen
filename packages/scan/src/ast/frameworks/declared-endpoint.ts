import ts from "typescript";
import { type EntryPoint, type FrameworkAdapter, type TaintSeed } from "../entrypoints.js";
import { collect, literalTextOf } from "../helpers.js";
import { lineOf, type ParsedFile } from "../parse.js";

/* ------------------------------------------------------------------------- *
 * The generic declared endpoint
 *
 * Seventeen adapters, one per framework, and Run 7 measured what that costs. On five
 * stacks nobody had written an adapter for — Firebase Cloud Functions, Azure Functions,
 * Strapi, Medusa, Encore — recall on classes whose sink is framework or store vocabulary
 * was 0.042, against 0.875 on classes whose sink is a Node primitive. The rules were
 * fine. The engine simply never learned which bindings held the caller's data, because
 * nothing in those files matched a shape it had been taught one framework at a time.
 *
 * Writing five more adapters would have raised that corpus and taught the engine nothing.
 * The sixth stack would read 0.042 again, and the corpus after it, forever: there is no
 * end to the supply of frameworks and there is no version of this project that has an
 * adapter for the one a reader is actually using.
 *
 * So this adapter recognises the thing all of them have in common, which is also how a
 * human reads an unfamiliar framework:
 *
 *   **a function that is handed to something, next to a path.**
 *
 *     app.http("permitDetail", { route: "api/permits/{permitId}", handler })   // Azure
 *     export const detail = api({ method: "GET", path: "/jobs/:jobID" }, fn)   // Encore
 *     export const centreHook = onRequest(async (request, response) => { … })  // Firebase
 *     export const GET = async (req: MedusaRequest, res: MedusaResponse) => {} // Medusa
 *
 * Two independent pieces of evidence are required together, and neither is a framework
 * name:
 *
 * 1. **A path.** A string literal shaped like a route — `/jobs/:jobID`,
 *    `api/permits/{permitId}`, `/v1/sites/[siteId]/exports` — or an export named after an
 *    HTTP verb, which is how file-routed frameworks spell the same thing.
 * 2. **A function** reached from the same expression: the value itself, an argument of
 *    the call, or a property of an object argument (`{ handler }`).
 *
 * A path without a function is a constant. A function without a path is a function. Only
 * the pair says "the outside world can reach this code", and that pair is what every HTTP
 * framework in this language has looked like for fifteen years.
 *
 * ## Why the whole request object is seeded
 *
 * `requestParameters` in the taint model admits a parameter whose *name* or *declared
 * type* says request — `req`, `ctx`, `HttpRequest`. That is right as a default and it is
 * not enough here, because the modern shape is a typed object of exactly the caller's
 * fields:
 *
 *     export const assign = api(
 *       { method: "POST", path: "/dispatch/jobs/:jobID/assignment" },
 *       async ({ jobID, assigneeID }: AssignRequest) => { … }
 *     )
 *
 * `jobID` is a path parameter and `assigneeID` came out of the body. Neither name is on
 * any list and neither ever will be, because they are this application's nouns. But the
 * inference needs no list: a path literal established that this function answers HTTP
 * requests, and every parameter of a function that answers HTTP requests holds what the
 * requester sent. That is not a heuristic about naming, it is the definition of a handler.
 *
 * Framework-supplied parameters are the exception and they are excluded by name, because
 * that is the one thing genuinely conventional across frameworks: the second parameter of
 * a Node-style handler is the response, and a few well-known containers carry the
 * server's own facilities rather than the caller's. Getting this wrong in the other
 * direction is the expensive mistake — seeding a response object or a service container
 * invents flows that no caller controls — so the exclusion list is applied to
 * `trustedParameters`, where the taint model already gives it precedence over seeds.
 * ------------------------------------------------------------------------- */

const FRAMEWORK = "declared-endpoint";

/**
 * A string literal shaped like a route.
 *
 * Deliberately tolerant about the leading slash: Azure declares `route: "api/permits"`
 * with none, Encore declares `path: "/jobs/:jobID"` with one, and refusing the first
 * would have been a framework-specific decision dressed up as a format rule.
 *
 * Deliberately intolerant of everything a path can be confused with. A URL is excluded
 * by the scheme test, because `https://api.example.com/v1` names somebody else's
 * endpoint rather than one of ours and seeding a client call as a handler would be a
 * false positive with a very confident-looking route attached. A bare word is excluded by
 * requiring a separator, which keeps `"users"` from reading as a route. A glob, a
 * selector and a file path are excluded by the character class.
 */
const ROUTE_SHAPE = /^\/?[A-Za-z0-9\-_.~]+(?:\/[A-Za-z0-9\-_.~:{}[\]$*]*)+\/?$/;
const NOT_A_ROUTE = /^(?:[a-z][a-z0-9+.-]*:)|^\/\/|\.(?:[jt]sx?|mjs|cjs|json|sql|html|css|md|png|jpe?g|svg)$|\*\*|^\.{1,2}\//i;

/** Properties whose value is where a framework puts the address. */
const PATH_PROPERTY = new Set(["path", "route", "url", "pattern", "endpoint"]);

/** Properties whose value is the function that answers the request. */
const HANDLER_PROPERTY = new Set(["handler", "handle", "resolve", "run", "action", "loader", "callback", "fn"]);

const HTTP_VERBS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]);

const STATE_CHANGING = new Set(["POST", "PUT", "PATCH", "DELETE"]);

/**
 * Parameters that belong to the server rather than to the caller.
 *
 * The cost of a mistake is asymmetric. Missing a seed loses one finding; seeding the
 * response object or a dependency container invents a flow from the framework's own
 * facilities into every sink in the handler, and does it in every file at once. So this
 * list is applied as `trustedParameters` — which the taint model resolves *before* seeds
 * — and it is allowed to be conservative.
 */
const SERVER_SUPPLIED = new Set([
  "res",
  "response",
  "reply",
  "send",
  "next",
  "resolve",
  "reject",
  "done",
  "callback",
  "cb",
  "logger",
  "log",
  "container",
  "scope",
  "services",
  "strapi",
  "app",
  "server",
  "config",
  "env",
  "deps",
  "injector",
  "invocationContext",
  "executionContext",
  "lambdaContext"
]);

/**
 * Is this expression's own text a route?
 *
 * Reads only string literals. A template with an interpolation is not an address a
 * reader can look up, and treating one as a route would print a path that appears
 * nowhere in the application.
 */
function routeTextOf(node: ts.Node): string | null {
  if (!ts.isStringLiteralLike(node)) return null;
  const text = node.text.trim();
  if (text.length < 2 || text.length > 200) return null;
  if (NOT_A_ROUTE.test(text)) return null;
  return ROUTE_SHAPE.test(text) ? text : null;
}

function propertyValue(object: ts.ObjectLiteralExpression, names: ReadonlySet<string>): ts.Expression | undefined {
  for (const property of object.properties) {
    if (ts.isPropertyAssignment(property) && ts.isIdentifier(property.name) && names.has(property.name.text)) {
      return property.initializer;
    }
    if (ts.isShorthandPropertyAssignment(property) && names.has(property.name.text)) return property.name;
    if (ts.isMethodDeclaration(property) && ts.isIdentifier(property.name) && names.has(property.name.text)) {
      return property.name;
    }
  }
  return undefined;
}

/** The verb a route object declares, if it declares one. */
function methodOf(object: ts.ObjectLiteralExpression): string | null {
  for (const property of object.properties) {
    if (!ts.isPropertyAssignment(property)) continue;
    if (!ts.isIdentifier(property.name)) continue;
    if (property.name.text !== "method" && property.name.text !== "methods") continue;
    const single = literalTextOf(property.initializer);
    if (single && HTTP_VERBS.has(single.toUpperCase())) return single.toUpperCase();
    if (ts.isArrayLiteralExpression(property.initializer)) {
      const verbs = property.initializer.elements
        .map((element) => literalTextOf(element))
        .filter((value): value is string => value !== null && HTTP_VERBS.has(value.toUpperCase()));
      // Several verbs on one handler: `ANY` is the honest label, because naming the
      // first would send a reader to probe one address and miss the others.
      if (verbs.length === 1) return verbs[0]!.toUpperCase();
      if (verbs.length > 1) return "ANY";
    }
  }
  return null;
}

function isFunctionLike(node: ts.Node): node is ts.FunctionLikeDeclaration {
  return ts.isArrowFunction(node) || ts.isFunctionExpression(node) || ts.isFunctionDeclaration(node);
}

/**
 * The route and the handler reached from one expression.
 *
 * Searched one call deep rather than recursively. A registration is written as a single
 * expression by every framework that has one, and walking arbitrarily far would start
 * pairing a path from one statement with a callback from another — a route label that
 * points at code which never runs for it.
 */
interface Declaration {
  route: string;
  method: string | null;
  handler: ts.FunctionLikeDeclaration;
  /** Everything else the registration declared: options, middleware, policies. */
  gate: ts.Node[];
}

function declarationIn(expression: ts.Expression): Declaration | null {
  if (!ts.isCallExpression(expression)) return null;

  let route: string | null = null;
  let method: string | null = null;
  let handler: ts.FunctionLikeDeclaration | null = null;
  let named: ts.Identifier | null = null;

  for (const argument of expression.arguments) {
    const direct = routeTextOf(argument);
    if (direct && !route) {
      route = direct;
      continue;
    }
    if (isFunctionLike(argument) && !handler) {
      handler = argument;
      continue;
    }
    if (ts.isObjectLiteralExpression(argument)) {
      const declaredPath = propertyValue(argument, PATH_PROPERTY);
      if (declaredPath && !route) route = routeTextOf(declaredPath);
      method ??= methodOf(argument);
      const declaredHandler = propertyValue(argument, HANDLER_PROPERTY);
      if (declaredHandler && !handler) {
        if (isFunctionLike(declaredHandler)) handler = declaredHandler;
        else if (ts.isIdentifier(declaredHandler)) named = declaredHandler;
      }
    }
  }

  if (!route) return null;
  if (!handler && named) handler = resolveLocalFunction(expression.getSourceFile(), named.text);
  if (!handler) return null;
  /*
   * Everything in the registration that is neither the path nor the handler.
   *
   * Kept whole rather than filtered down to the properties that look like middleware:
   * the access rules already know how to read a gate expression, every framework names
   * the option differently, and a list of names here would be the exact mistake this
   * adapter exists to avoid.
   */
  const gate = expression.arguments.filter((argument) => argument !== handler && routeTextOf(argument) === null);
  return { route, method, handler, gate };
}

/**
 * `{ handler: monthlySweep }` where `monthlySweep` is declared in the same file.
 *
 * Azure's own documentation writes registrations this way and it is the shape a file with
 * more than one endpoint tends toward, so refusing it would have meant recognising the
 * toy example and not the real one.
 */
function resolveLocalFunction(source: ts.SourceFile, name: string): ts.FunctionLikeDeclaration | null {
  for (const statement of source.statements) {
    if (ts.isFunctionDeclaration(statement) && statement.name?.text === name) return statement;
    if (!ts.isVariableStatement(statement)) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (!ts.isIdentifier(declaration.name) || declaration.name.text !== name) continue;
      if (declaration.initializer && isFunctionLike(declaration.initializer)) return declaration.initializer;
    }
  }
  return null;
}

/** Every binding a handler's parameters introduce, and which of them are the server's. */
function bindingsOf(handler: ts.FunctionLikeDeclaration, route: string): { seeds: TaintSeed[]; trusted: string[] } {
  const seeds: TaintSeed[] = [];
  const trusted: string[] = [];
  const parameters = handler.parameters ?? ts.factory.createNodeArray([]);

  parameters.forEach((parameter, index) => {
    if (ts.isIdentifier(parameter.name)) {
      const name = parameter.name.text;
      // The second positional parameter of a Node-style handler is the response. That
      // convention is older than any framework here and holds across all of them.
      if (SERVER_SUPPLIED.has(name) || (index === 1 && parameters.length === 2 && !ts.isObjectBindingPattern(parameter.name))) {
        trusted.push(name);
        return;
      }
      seeds.push({ name, origin: `${name} (request to ${route})` });
      return;
    }
    if (ts.isObjectBindingPattern(parameter.name)) {
      for (const element of parameter.name.elements) {
        if (!ts.isIdentifier(element.name)) continue;
        const source =
          element.propertyName && ts.isIdentifier(element.propertyName) ? element.propertyName.text : element.name.text;
        if (SERVER_SUPPLIED.has(source)) {
          trusted.push(element.name.text);
          continue;
        }
        seeds.push({ name: element.name.text, origin: `${element.name.text} (request to ${route})` });
      }
    }
  });

  return { seeds, trusted };
}

/**
 * Does this file already declare its endpoints in a way another adapter recognises?
 *
 * Asked so that a Nitro or a Hapi file does not receive a second, worse-labelled entry
 * point for the same handler from this adapter. `applies` cannot answer it — the registry
 * runs every adapter whose text pre-check passes — so the answer is the specific
 * registration shapes this one would duplicate.
 *
 * `app.get("/x", handler)` is deliberately *not* excluded here. An Express-style
 * registration is recognised by the access rules' own endpoint model rather than by an
 * adapter, and that model reads routes, not seeds, so both are wanted.
 */
const OWNED_ELSEWHERE = /\bdefineEventHandler\s*\(|\bserver\s*\.\s*route\s*\(|\bcreateServerFn\s*\(|\bdefineAction\s*\(/;

export const declaredEndpointAdapter: FrameworkAdapter = {
  id: FRAMEWORK,
  applies(file: ParsedFile): boolean {
    if (OWNED_ELSEWHERE.test(file.text)) return false;
    // A route-shaped literal has to be present as text before it is worth walking the
    // tree: this adapter runs on every file in every project, and the pre-check is what
    // keeps that affordable.
    return /["'`]\/?[A-Za-z0-9\-_.~]+\//.test(file.text);
  },
  detect(file: ParsedFile): EntryPoint[] {
    const out: EntryPoint[] = [];
    const seen = new Set<ts.Node>();

    const add = (declaration: Declaration, anchor: ts.Node, verbFromName: string | null): void => {
      if (seen.has(declaration.handler)) return;
      seen.add(declaration.handler);
      const { seeds, trusted } = bindingsOf(declaration.handler, declaration.route);
      // A handler with nothing caller-controlled in its signature is not a finding
      // waiting to happen, and claiming an entry point for it would add a route label to
      // the report and no analysis behind it.
      if (seeds.length === 0) return;
      const method = declaration.method ?? verbFromName ?? "ANY";
      out.push({
        framework: FRAMEWORK,
        kind: "http",
        ...(declaration.gate.length > 0 ? { gate: declaration.gate } : {}),
        method,
        path: declaration.route.startsWith("/") ? declaration.route : `/${declaration.route}`,
        line: lineOf(file, anchor),
        node: declaration.handler,
        seeds,
        ...(trusted.length > 0 ? { trustedParameters: trusted } : {}),
        stateChanging: STATE_CHANGING.has(method)
      } as EntryPoint);
    };

    for (const statement of file.source.statements) {
      const exported = ts.canHaveModifiers(statement)
        ? (ts.getModifiers(statement) ?? []).some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword)
        : false;

      if (ts.isVariableStatement(statement)) {
        for (const declaration of statement.declarationList.declarations) {
          if (!declaration.initializer) continue;
          const name = ts.isIdentifier(declaration.name) ? declaration.name.text : null;
          const verb = exported && name && HTTP_VERBS.has(name.toUpperCase()) ? name.toUpperCase() : null;

          const found = declarationIn(declaration.initializer);
          if (found) {
            add(found, declaration, verb);
            continue;
          }
          /*
           * A file-routed handler — `export const GET = async (req, res) => …` — is
           * deliberately *not* claimed here.
           *
           * There is no path in the file because the path is the file's own location, and
           * `routeFromFilePath` is what knows how to turn one into the other. Naming the
           * file as the route looked harmless and was not: it produced an entry point
           * whose `path` was `app/api/thumbnail/route.ts`, which then won attribution over
           * the real `POST /api/thumbnail` and printed a filename where a reader needed an
           * address. The file-route model already handles this shape; the fix for a
           * convention it does not yet know belongs in `routeFromFilePath`, in one place,
           * for every rule at once.
           */
        }
        continue;
      }

      if (ts.isExpressionStatement(statement)) {
        const found = declarationIn(statement.expression as ts.Expression);
        if (found) add(found, statement, null);
      }
    }

    // Registrations nested inside another expression — an array of routes, a builder
    // chain, an `export default` object. Walked after the statement pass so the more
    // precise anchors above win, and gated on `seen` so nothing is reported twice.
    for (const call of collect(file.source, ts.isCallExpression)) {
      const found = declarationIn(call);
      if (found) add(found, call, null);
    }

    return out;
  }
};
