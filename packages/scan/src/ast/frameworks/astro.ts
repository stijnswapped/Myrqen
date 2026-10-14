import ts from "typescript";
import {
  allCalls,
  importsFrom,
  joinRoute,
  type EntryPoint,
  type FrameworkAdapter,
  type TaintSeed
} from "../entrypoints.js";
import { calleeTail } from "../helpers.js";
import { lineOf, type ParsedFile } from "../parse.js";

/* ------------------------------------------------------------------------- *
 * Astro's server surface: file-routed endpoints, actions, and middleware.
 *
 * Nothing in an Astro server module registers a route, and nothing in it is
 * called `req`. The address of `src/pages/api/link-preview.ts` exists nowhere
 * but in that file's own path, so a scanner reading the AST alone can see the
 * whole handler and still have no endpoint to report it against. And a file
 * with no entry point is not merely unlabelled — it has no request parameter,
 * so it has no taint, so every data-flow rule in the engine stays silent over a
 * handler that fetches a URL the caller chose.
 *
 * The input side is the half that has to be got exactly right. An endpoint
 * receives one APIContext, almost always destructured, and the keys of that bag
 * are not equally trustworthy: `request`, `params`, `url` and `cookies` are
 * whatever the caller sent, while `locals` is whatever the auth middleware
 * decided to attach and `redirect` is a function the framework supplied.
 * Seeding the wrong half of that bag would put attacker control on the resolved
 * session, which is exactly the value a correctly scoped query is supposed to be
 * filtered by, so the distinction is declared here rather than guessed at
 * downstream.
 *
 * Actions are the same problem in a different shape. `defineAction({ input,
 * handler })` has no URL at all — it is addressed by the key it is bound to
 * under `server` — its caller data arrives as the handler's first argument
 * whatever that argument happens to be named, and its second argument is a
 * context carrying both the inbound request and the server's own `locals` on
 * one object.
 * ------------------------------------------------------------------------- */

/**
 * The exports Astro serves a request from, and the verb each answers.
 *
 * `ALL` answers every method that has no export of its own, so it has no single
 * verb; reporting it as ANY is the honest reading and stops a reader believing a
 * specific method was checked. `HEAD` and `OPTIONS` are here because Astro will
 * dispatch to them when they are exported, even though the guide only spells out
 * the four common verbs.
 */
const METHOD_EXPORTS = new Map<string, string>([
  ["GET", "GET"],
  ["POST", "POST"],
  ["PUT", "PUT"],
  ["PATCH", "PATCH"],
  ["DELETE", "DELETE"],
  ["HEAD", "HEAD"],
  ["OPTIONS", "OPTIONS"],
  ["ALL", "ANY"]
]);

/**
 * APIContext keys that hold data the caller chose, with the wording quoted
 * verbatim in evidence.
 *
 * The list is deliberately short. `locals`, `props`, `site`, `generator`,
 * `session`, `currentLocale` and `routePattern` are all produced by the server
 * or by the build, and `clientAddress` is read off the connection by the adapter
 * rather than chosen by whoever is calling. Seeding any of them would invent a
 * flow the caller never influenced, across every data-flow rule at once.
 */
const CONTEXT_SEEDS = new Map<string, string>([
  ["params", "context.params (caller-controlled route parameters)"],
  ["request", "context.request (inbound request)"],
  ["url", "context.url (caller-controlled request URL)"],
  ["cookies", "context.cookies (caller-controlled cookies)"]
]);

/**
 * Keys the generic parameter model would otherwise read as caller data.
 *
 * `locals` is what the middleware attached — a resolved session, a tenant, a
 * database handle — and `redirect` is a framework-supplied function, not a
 * value at all. Naming them here keeps a handler written `({ request, locals })`
 * from having its session treated as attacker input.
 */
const SERVER_SUPPLIED_CONTEXT_KEYS = new Set(["locals", "redirect"]);

/** What an endpoint or action handler binds out of the context it was handed. */
interface ContextBindings {
  seeds: TaintSeed[];
  trusted: string[];
}

/**
 * Astro routes `.js` and `.ts` files under `src/pages`, and nothing else.
 *
 * `.astro` is a page rather than an endpoint and never exports a verb, and
 * `.tsx` under `src/pages` belongs to some other framework's router — claiming
 * either would put addresses in the report that no Astro request can reach.
 */
const ENDPOINT_EXTENSION = /\.[cm]?[jt]s$/;

/** The modules that only an Astro project imports. */
const ASTRO_MODULES = /^astro$|^astro:/;
const ASTRO_ACTIONS_MODULE = /^astro:actions$/;
const ASTRO_MIDDLEWARE_MODULE = /^astro:middleware$/;

/* --------------------------- addresses from paths --------------------------- */

/**
 * The URL an endpoint file answers on, read from its own location.
 *
 * The bracket syntax is kept exactly as the directory spells it — `[id]`,
 * `[...rest]` — because that is what the developer wrote, what the Astro docs
 * call it, and what they will search the report for; rewriting it to `:id`
 * produces a path that matches nothing anybody typed. `index` addresses the
 * directory it sits in rather than a segment of its own, and a segment prefixed
 * with `_` is excluded from routing by Astro itself, so a file under one is a
 * private helper and not an endpoint at all.
 *
 * `requireSrc` is what separates Astro from Next.js, which also routes a
 * `pages` directory. Only a scan rooted below `src/` loses the `src` segment,
 * and for that case the caller re-runs this loosely once the file's imports have
 * settled that the framework really is Astro.
 */
function pagesRoute(relativePath: string, requireSrc: boolean): string | null {
  const parts = relativePath.split("/").filter((part) => part.length > 0);
  const fileName = parts.pop();
  if (!fileName || !ENDPOINT_EXTENSION.test(fileName)) return null;

  let root = -1;
  for (let index = parts.length - 1; index >= 0; index -= 1) {
    if (parts[index] !== "pages") continue;
    if (requireSrc && parts[index - 1] !== "src") continue;
    root = index;
    break;
  }
  if (root === -1) return null;

  const inside = parts.slice(root + 1);
  if ([...inside, fileName].some((segment) => segment.startsWith("_"))) return null;

  const base = fileName.replace(ENDPOINT_EXTENSION, "");
  const leaf = base === "index" ? [] : [base];
  return joinRoute(...inside, ...leaf);
}

/** Does this path sit in a directory whose name Astro reserves for one purpose? */
function isUnder(relativePath: string, directory: string): boolean {
  const parts = relativePath.split("/").filter((part) => part.length > 0);
  return parts.some((part, index) => part === directory && parts[index - 1] === "src");
}

/**
 * `src/middleware.ts`, or the directory form of the same module.
 *
 * Next.js puts a file at exactly this path too, which is why the path alone
 * never settles anything here: an entry point is only claimed once an
 * `onRequest` export or a `defineMiddleware` call has been found, and Next's
 * middleware exports neither.
 */
function isMiddlewarePath(relativePath: string): boolean {
  const parts = relativePath.split("/").filter((part) => part.length > 0);
  const fileName = parts.pop() ?? "";
  const base = fileName.replace(ENDPOINT_EXTENSION, "");
  if (base === "middleware" && parts[parts.length - 1] === "src") return true;
  return base === "index" && isUnder(relativePath, "middleware");
}

/* ----------------------------- export plumbing ----------------------------- */

interface ExportedBinding {
  name: string;
  /** The node to blame in the report, so the line points at the export. */
  declaration: ts.Node;
  /** The exported value, before any type wrapper is peeled off. */
  value: ts.Expression | undefined;
  /** The function whose body runs, when the export resolves to one. */
  fn: ts.Node | undefined;
}

function propertyKey(name: ts.PropertyName | undefined): string | null {
  if (!name) return null;
  if (ts.isIdentifier(name)) return name.text;
  if (ts.isStringLiteralLike(name)) return name.text;
  return null;
}

function hasExportModifier(node: ts.Node): boolean {
  return (
    ts.canHaveModifiers(node) &&
    (ts.getModifiers(node) ?? []).some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword)
  );
}

/** The function-like node behind an expression, seeing through type wrappers. */
function functionBehind(node: ts.Node | undefined): ts.Node | undefined {
  if (!node) return undefined;
  if (ts.isArrowFunction(node) || ts.isFunctionExpression(node) || ts.isFunctionDeclaration(node)) return node;
  if (ts.isMethodDeclaration(node)) return node;
  // `export const GET = (async (context) => {}) satisfies APIRoute` is all the
  // same handler, and a model that stops at the first wrapper loses the body.
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
 * a re-export of a local name, and the CommonJS assignment a plain `.js` module
 * may still be written with. Recognising only the first would leave the others
 * with no entry point, which is the same as leaving them unscanned.
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
      // `export { handler as POST }`. A re-export that names another module
      // cannot be resolved from this file, so it is left alone.
      if (!ts.isNamedExports(statement.exportClause)) continue;
      for (const element of statement.exportClause.elements) {
        const resolved = localBinding(file, (element.propertyName ?? element.name).text);
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

    const target = assignment.left;
    if (!ts.isPropertyAccessExpression(target)) continue;

    // `exports.POST = handler` and `module.exports.POST = handler`.
    const receiver = target.expression;
    const isNamedExport =
      (ts.isIdentifier(receiver) && receiver.text === "exports") ||
      (ts.isPropertyAccessExpression(receiver) &&
        receiver.name.text === "exports" &&
        ts.isIdentifier(receiver.expression) &&
        receiver.expression.text === "module");
    if (isNamedExport) {
      found.push({
        name: target.name.text,
        declaration: statement,
        value: assignment.right,
        fn: functionBehind(assignment.right)
      });
      continue;
    }

    // `module.exports = { POST: handler }`
    if (target.name.text !== "exports") continue;
    if (!ts.isIdentifier(receiver) || receiver.text !== "module") continue;
    const literal = objectBehind(assignment.right);
    if (!literal) continue;
    for (const property of literal.properties) {
      const key = propertyKey(property.name);
      if (!key) continue;
      if (ts.isPropertyAssignment(property)) {
        found.push({ name: key, declaration: property, value: property.initializer, fn: functionBehind(property.initializer) });
        continue;
      }
      if (ts.isMethodDeclaration(property)) {
        found.push({ name: key, declaration: property, value: undefined, fn: property });
        continue;
      }
      if (ts.isShorthandPropertyAssignment(property)) {
        const resolved = localBinding(file, property.name.text);
        found.push({ name: key, declaration: property, value: resolved?.value, fn: resolved?.fn });
      }
    }
  }

  return found;
}

/**
 * The handler behind an export, following one layer of wrapping.
 *
 * `export const GET: APIRoute = withAuth(async (context) => {})` is how a
 * project shares a guard across its endpoints, and stopping at the call loses
 * the body along with every flow inside it. Only an unambiguous wrapper is
 * followed: with two function arguments there is no telling which one runs the
 * request and which is an error branch, and attaching the seeds to the wrong one
 * would put attacker control on a parameter that never holds it.
 */
function wrappedHandler(value: ts.Expression | undefined): ts.Node | undefined {
  if (!value || !ts.isCallExpression(value)) return undefined;
  const functions = value.arguments.map((argument) => functionBehind(argument)).filter((fn): fn is ts.Node => Boolean(fn));
  return functions.length === 1 ? functions[0] : undefined;
}

/* ---------------------------------- seeds ---------------------------------- */

/**
 * What a handler bound out of the APIContext it was handed.
 *
 * A plain identifier parameter is the whole context, so it is seeded whole: the
 * taint model already refuses `context.locals`, and declaring the parameter
 * trusted instead would suppress the request data sitting on the same object. A
 * destructured parameter has no root to name, so each key is judged on its own
 * and the name recorded is the *bound* name — `{ params: routeParams }` puts the
 * route parameters in `routeParams`, and a seed on `params` would mark a binding
 * that does not exist.
 */
function contextBindings(fn: ts.Node | undefined, index: number): ContextBindings {
  const parameter = (fn as ts.FunctionLikeDeclaration | undefined)?.parameters?.[index];
  if (!parameter) return { seeds: [], trusted: [] };

  if (ts.isIdentifier(parameter.name)) {
    return { seeds: [{ name: parameter.name.text, origin: "context (inbound request)" }], trusted: [] };
  }
  if (!ts.isObjectBindingPattern(parameter.name)) return { seeds: [], trusted: [] };

  const seeds: TaintSeed[] = [];
  const trusted: string[] = [];
  for (const element of parameter.name.elements) {
    // `...rest` carries whichever context keys were not named above it, and which
    // ones those are cannot be known here. A guess would seed a binding that may
    // hold nothing but `site` and `generator`.
    if (element.dotDotDotToken) continue;
    // A nested pattern binds something *inside* a context key, and whether that
    // inner value is caller data depends on the key it came from.
    if (!ts.isIdentifier(element.name)) continue;

    const key = propertyKey(element.propertyName ?? element.name);
    if (!key) continue;
    const origin = CONTEXT_SEEDS.get(key);
    if (origin) {
      seeds.push({ name: element.name.text, origin });
      continue;
    }
    if (SERVER_SUPPLIED_CONTEXT_KEYS.has(key)) trusted.push(element.name.text);
  }
  return { seeds, trusted };
}

/**
 * The action input, which is caller data all the way down.
 *
 * Unlike a context bag, every key of an action's input came off the wire: the
 * schema proves the shape, never the provenance. So a destructured input seeds
 * each bound name, and a rest element is seeded too — it holds the keys the
 * caller sent that the handler did not name individually.
 */
function inputSeeds(fn: ts.Node | undefined): TaintSeed[] {
  const parameter = (fn as ts.FunctionLikeDeclaration | undefined)?.parameters?.[0];
  if (!parameter) return [];

  const whole = "input (caller-supplied action input)";
  if (ts.isIdentifier(parameter.name)) return [{ name: parameter.name.text, origin: whole }];
  if (!ts.isObjectBindingPattern(parameter.name)) return [];

  const seeds: TaintSeed[] = [];
  for (const element of parameter.name.elements) {
    if (!ts.isIdentifier(element.name)) continue;
    if (element.dotDotDotToken) {
      seeds.push({ name: element.name.text, origin: whole });
      continue;
    }
    const key = propertyKey(element.propertyName ?? element.name);
    seeds.push({
      name: element.name.text,
      origin: key ? `input.${key} (caller-supplied action input)` : whole
    });
  }
  return seeds;
}

function entryPoint(
  kind: EntryPoint["kind"],
  method: string,
  path: string,
  line: number,
  fn: ts.Node | undefined,
  bindings: ContextBindings
): EntryPoint {
  return {
    framework: "astro",
    kind,
    method,
    path,
    line,
    ...(fn ? { node: fn } : {}),
    ...(bindings.seeds.length > 0 ? { seeds: bindings.seeds } : {}),
    ...(bindings.trusted.length > 0 ? { trustedParameters: bindings.trusted } : {})
  };
}

/* -------------------------------- endpoints -------------------------------- */

function endpointEntries(file: ParsedFile, importsAstro: boolean): EntryPoint[] {
  const route = pagesRoute(file.relativePath, true) ?? (importsAstro ? pagesRoute(file.relativePath, false) : null);
  if (route === null) return [];

  const found: EntryPoint[] = [];
  for (const binding of exportedBindings(file)) {
    const method = METHOD_EXPORTS.get(binding.name);
    if (!method) continue;

    const fn = binding.fn ?? wrappedHandler(binding.value);
    // An export the file cannot resolve to a body is still an address a reader
    // can act on, so the route is reported without seeds. A verb-named export
    // holding something that is plainly not a handler — `export const ALL = 3` —
    // is not an endpoint at all and is left alone.
    if (!fn && binding.value && !ts.isCallExpression(binding.value) && !ts.isIdentifier(binding.value)) continue;

    const bindings = fn ? contextBindings(fn, 0) : { seeds: [], trusted: [] };
    found.push(entryPoint("http", method, route, lineOf(file, binding.declaration), fn, bindings));
  }
  return found;
}

/* ---------------------------------- actions ---------------------------------- */

/**
 * The key an action is addressed by.
 *
 * An action's name is spelled by the object structure it is bound into under
 * `server`, and property keys are part of that address: a nested group really is.
 *
 * **An exported variable holding a group is also part of it.** The commonest way
 * an Astro application is laid out is one module per group —
 * `export const giftCards = { applyToOrder: defineAction(…) }` — which
 * `src/actions/index.ts` then re-exports into `server` under that same name. An
 * earlier version of this function returned the property keys alone and dropped the
 * variable, on the reasoning that "the variable an object happens to be assigned to"
 * is not an address. That is true of a local, and wrong of an export: an export is
 * how the group gets its name in the first place. So an exported declaration
 * contributes its name, and a local one still does not.
 *
 * A bare `export const placeOrder = defineAction(…)` falls back to the only name it
 * has, which is correct — there is no group.
 *
 * The limitation, stated rather than guessed at: if `index.ts` re-exports the group
 * under a *different* key, the address is that key and this cannot know it. That is
 * the same boundary the engine already declares for a router mounted under a prefix
 * in another module, and it is disclosed in the same coverage note.
 */
/** The name Astro requires `src/actions/index.ts` to export the root object under. */
const ACTIONS_ROOT_EXPORT = "server";

function actionName(call: ts.CallExpression): string | null {
  const keys: string[] = [];
  let variableName: string | null = null;
  let node: ts.Node = call;
  let parent: ts.Node | undefined = node.parent;

  for (let depth = 0; parent && depth < 12; depth += 1) {
    if (ts.isPropertyAssignment(parent) && parent.initializer === node) {
      const key = propertyKey(parent.name);
      if (!key) break;
      keys.push(key);
    } else if (ts.isVariableDeclaration(parent) && parent.initializer === node && ts.isIdentifier(parent.name)) {
      variableName = parent.name.text;
      /*
       * `server` is Astro's mandated name for the actions root, not a group, so it
       * is never part of an address — `export const server = { user: { create } }`
       * is called as `actions.user.create`.
       *
       * Otherwise: only an *exported* group names the address. A local object the
       * actions happen to be assembled in is scaffolding, and an export is how a
       * group gets its name in the first place.
       */
      if (variableName === ACTIONS_ROOT_EXPORT) variableName = null;
      else if (keys.length > 0 && !isExportedDeclaration(parent)) variableName = null;
      break;
    } else if (
      !ts.isObjectLiteralExpression(parent) &&
      !ts.isAsExpression(parent) &&
      !ts.isSatisfiesExpression(parent) &&
      !ts.isParenthesizedExpression(parent)
    ) {
      break;
    }
    node = parent;
    parent = node.parent;
  }

  const dotted = keys.reverse();
  if (variableName) dotted.unshift(variableName);
  return dotted.length > 0 ? dotted.join(".") : null;
}

/** Is this declaration's statement exported? */
function isExportedDeclaration(declaration: ts.VariableDeclaration): boolean {
  const statement = declaration.parent?.parent;
  if (!statement || !ts.isVariableStatement(statement)) return false;
  return statement.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword) === true;
}

/**
 * The URL an action is actually reachable at.
 *
 * Astro serves every action from one endpoint — `POST /_actions/<dotted name>` — so
 * that is the address a reader needs in order to probe it, and reporting the bare
 * name gives them a handler with no way to reach it. It also means the address is a
 * path rather than a procedure name, so it carries its verb like any other route.
 */
function actionRoute(name: string): string {
  return `/_actions/${name}`;
}

/** Does this options object declare the given member at all, whatever it holds? */
function hasMember(object: ts.ObjectLiteralExpression, key: string): boolean {
  return object.properties.some((property) => {
    if (ts.isShorthandPropertyAssignment(property)) return property.name.text === key;
    return propertyKey(property.name) === key;
  });
}

/** The function held by one member of an options object, in any of its spellings. */
function memberFunction(file: ParsedFile, object: ts.ObjectLiteralExpression, key: string): ts.Node | undefined {
  for (const property of object.properties) {
    if (ts.isShorthandPropertyAssignment(property)) {
      // `defineAction({ input, handler })` puts the body somewhere above, and
      // without resolving it the action has no seeds at all.
      if (property.name.text === key) return localBinding(file, property.name.text)?.fn;
      continue;
    }
    if (propertyKey(property.name) !== key) continue;
    if (ts.isMethodDeclaration(property)) return property;
    if (ts.isPropertyAssignment(property)) return functionBehind(property.initializer);
  }
  return undefined;
}

function actionEntries(file: ParsedFile): EntryPoint[] {
  const found: EntryPoint[] = [];

  for (const call of allCalls(file)) {
    if (calleeTail(call) !== "defineAction") continue;
    const options = objectBehind(call.arguments[0]);
    // `handler` is the whole of Astro's contract for an action, so a call that
    // declares none is some other library's `defineAction` and has no body this
    // adapter can speak for. `src/actions` is a directory Redux projects use too,
    // and claiming one of those would seed a reducer's argument as caller input.
    if (!options || !hasMember(options, "handler")) continue;

    const handler = memberFunction(file, options, "handler");
    const name = actionName(call);
    // A `accept: "form"` action is handled by the same code as a JSON one: the
    // handler still receives the submission as its first argument, parsed when a
    // schema is declared and raw FormData when one is not, and either way it is
    // the caller's.
    const context = contextBindings(handler, 1);
    found.push(
      entryPoint(
        "action",
        "POST",
        name === null ? "action" : actionRoute(name),
        lineOf(file, call),
        handler,
        { seeds: [...inputSeeds(handler), ...context.seeds], trusted: context.trusted }
      )
    );
  }

  return found;
}

/* --------------------------------- middleware --------------------------------- */

/**
 * Astro middleware runs on every request, so it is reported as `ANY /` in the
 * same spirit as a Nitro middleware: it is not addressable on its own, and
 * pretending it answers one route would send a reader to the wrong place. It is
 * still where a request first meets application code, which is why the context
 * it reads has to be seeded.
 */
function middlewareEntries(file: ParsedFile): EntryPoint[] {
  const found: EntryPoint[] = [];
  const wrapped = new Set<ts.Node>();

  for (const call of allCalls(file)) {
    if (calleeTail(call) !== "defineMiddleware") continue;
    const fn = functionBehind(call.arguments[0]);
    if (!fn) continue;
    wrapped.add(fn);
    found.push(entryPoint("http", "ANY", "/", lineOf(file, call), fn, contextBindings(fn, 0)));
  }

  for (const binding of exportedBindings(file)) {
    if (binding.name !== "onRequest") continue;
    const fn = binding.fn;
    // `export const onRequest = defineMiddleware(…)` and
    // `export const onRequest = sequence(a, b)` are both already accounted for:
    // the first by the loop above, the second by whichever of `a` and `b` is
    // itself a middleware declared in this file.
    if (!fn || wrapped.has(fn)) continue;
    found.push(entryPoint("http", "ANY", "/", lineOf(file, binding.declaration), fn, contextBindings(fn, 0)));
  }

  return found;
}

/* ---------------------------------- wiring ---------------------------------- */

/** Cheap text pre-checks, so this adapter does not walk every file's AST. */
const ASTRO_MODULE_MENTION = /(?:from|import|require\s*\()\s*["'](?:astro|astro:[a-z]+)["']/;
const DEFINE_ACTION_MENTION = /\bdefineAction\s*[<(]/;
const MIDDLEWARE_MENTION = /\bdefineMiddleware\s*[<(]|\bonRequest\b/;
const EXPORT_MENTION = /\bexports?\b/;
const VERB_MENTION = /\b(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|ALL)\b/;

function applies(file: ParsedFile): boolean {
  const mentionsAstroModule = ASTRO_MODULE_MENTION.test(file.text);

  // An action or a middleware can be written anywhere the project keeps it, so
  // the import is what settles those; the reserved directory is accepted too
  // because `src/actions` exists for one purpose only.
  if (DEFINE_ACTION_MENTION.test(file.text) && (mentionsAstroModule || isUnder(file.relativePath, "actions"))) return true;
  if (MIDDLEWARE_MENTION.test(file.text) && (mentionsAstroModule || isMiddlewarePath(file.relativePath))) return true;

  // An endpoint has to be placed by its path, so a file that is not in a routed
  // tree cannot be one however it is written.
  if (!EXPORT_MENTION.test(file.text) || !VERB_MENTION.test(file.text)) return false;
  if (pagesRoute(file.relativePath, true) !== null) return true;
  return mentionsAstroModule && pagesRoute(file.relativePath, false) !== null;
}

function detect(file: ParsedFile): EntryPoint[] {
  const importsAstro = importsFrom(file, ASTRO_MODULES);
  const found = endpointEntries(file, importsAstro);

  // `defineAction` and `defineMiddleware` are names some other library could
  // plausibly reuse, so outside Astro's own reserved directories the import is
  // required before either is claimed.
  if (importsFrom(file, ASTRO_ACTIONS_MODULE) || isUnder(file.relativePath, "actions")) {
    found.push(...actionEntries(file));
  }
  if (importsFrom(file, ASTRO_MIDDLEWARE_MODULE) || isMiddlewarePath(file.relativePath)) {
    found.push(...middlewareEntries(file));
  }

  return found;
}

export const astroAdapter: FrameworkAdapter = { id: "astro", applies, detect };
