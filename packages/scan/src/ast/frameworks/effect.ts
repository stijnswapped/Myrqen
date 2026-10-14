import ts from "typescript";
import { functionOf, importsFrom, type EntryPoint, type FrameworkAdapter } from "../entrypoints.js";
import { calleeName, calleeTail, collect, literalTextOf } from "../helpers.js";
import { lineOf, type ParsedFile } from "../parse.js";

/* ------------------------------------------------------------------------- *
 * Effect and @effect/platform
 *
 * Effect defeats every assumption the generic request model makes, in three
 * separate ways, and all three have to be answered or the file is invisible.
 *
 * **There is no request parameter.** A handler is an `Effect`, not a function of a
 * request: `HttpRouter.get("/x", Effect.gen(function* () { … }))`. The generator
 * takes no arguments at all, so a model looking for a parameter named `req` finds
 * nothing to seed and every data-flow rule stays quiet.
 *
 * **The request arrives through the context.** Caller data is obtained by yielding
 * an accessor — `yield* HttpServerRequest.schemaSearchParams(Filters)` — which is
 * neither a property of a parameter nor a bare function handed one. The accessor
 * list below is what turns those into caller data, and it is recorded per entry
 * point because `schemaBodyJson` means nothing in a file that is not Effect.
 *
 * **Every read is behind a `yield*`.** The engine unwrapped `await` and not `yield`
 * until this adapter was written, so even a correctly seeded value was lost at the
 * first statement. That fix is in the taint model rather than here, because it is
 * true of any generator-based code and not of Effect in particular.
 *
 * Deliberately not claimed: `Effect.gen` blocks that are not handlers. A layer, a
 * service constructor and a test are all written the same way, and seeding them would
 * invent caller data in code no caller reaches.
 * ------------------------------------------------------------------------- */

const FRAMEWORK = "effect";

/**
 * The accessors that return what the caller sent.
 *
 * Excluded on purpose: `HttpServerRequest.HttpServerRequest` yields the request
 * *service*, which is a handle rather than data, and the `remoteAddress` and
 * `cookies` service accessors are read through it. Anything named for the session or
 * the authenticated subject is server-derived and seeding it would disarm the
 * ownership checks written against it.
 */
const EFFECT_ACCESSORS = [
  "schemaSearchParams",
  "schemaBodyJson",
  "schemaBodyForm",
  "schemaBodyUrlParams",
  "schemaBodyMultipart",
  "schemaHeaders",
  "schemaPathParams",
  "schemaCookies",
  "urlParamsBody",
  "arrayBuffer",
  "json",
  "text",
  "urlParams"
];

const VERBS = new Set(["get", "post", "put", "patch", "del", "head", "options", "all"]);

/** `HttpRouter.del` is DELETE; the rest map onto themselves. */
function verbOf(tail: string): string {
  if (tail === "del") return "DELETE";
  if (tail === "all") return "ANY";
  return tail.toUpperCase();
}

/**
 * The generator or function body an Effect handler runs.
 *
 * `Effect.gen(function* () {…})` is the overwhelmingly common form. `Effect.fn`,
 * `Effect.flatMap(…, (x) => …)` and a bare `Effect.succeed` all appear too; only the
 * ones with a body worth scoping are returned, because an entry point whose node is
 * not a function gives the rules nothing to analyse.
 */
function handlerBody(node: ts.Node | undefined): ts.Node | undefined {
  if (!node) return undefined;
  const direct = functionOf(node);
  if (direct) return direct;
  if (!ts.isCallExpression(node)) return undefined;
  const tail = calleeTail(node);
  if (tail === "gen" || tail === "fn" || tail === "fnUntraced" || tail === "suspend") {
    // `Effect.gen(function* () {…})`, and the `(this, function* …)` overload.
    for (const argument of node.arguments) {
      const fn = functionOf(argument);
      if (fn) return fn;
    }
  }
  // `Effect.gen(…).pipe(…)` — the handler is still the generator inside.
  if (tail === "pipe" && ts.isPropertyAccessExpression(node.expression)) {
    return handlerBody(node.expression.expression);
  }
  return undefined;
}

export const effectAdapter: FrameworkAdapter = {
  id: FRAMEWORK,
  applies: (file) =>
    importsFrom(file, /^@effect\//) ||
    (importsFrom(file, /^effect$/) && /\bHttpRouter\b|\bHttpApi(?:Endpoint|Group)?\b|\bHttpServerRequest\b/.test(file.text)),
  detect(file: ParsedFile): EntryPoint[] {
    const found: EntryPoint[] = [];

    for (const call of collect(file.source, ts.isCallExpression)) {
      const name = calleeName(call);
      const tail = calleeTail(call);
      if (!VERBS.has(tail)) continue;
      // `HttpRouter.get(...)` / `router.get(...)` after a namespace import. The
      // receiver has to look like a router, or every `array.get` in the file matches.
      if (!/(?:^|\.)(HttpRouter|HttpApiBuilder|router|api)$/i.test(name.slice(0, name.length - tail.length - 1))) continue;

      const pathArgument = call.arguments[0];
      const routePath = pathArgument ? literalTextOf(pathArgument) : null;
      if (!routePath || !routePath.startsWith("/")) continue;

      const node = handlerBody(call.arguments[1]);
      if (!node) continue;

      found.push({
        framework: FRAMEWORK,
        kind: "http",
        method: verbOf(tail),
        path: routePath,
        line: lineOf(file, node),
        node,
        accessorFunctions: EFFECT_ACCESSORS
      });
    }

    return found;
  }
};
