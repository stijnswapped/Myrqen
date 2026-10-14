import ts from "typescript";
import { functionOf, importsFrom, type EntryPoint, type FrameworkAdapter, type TaintSeed } from "../entrypoints.js";
import { calleeName, collect, literalTextOf } from "../helpers.js";
import { lineOf, type ParsedFile } from "../parse.js";

/* ------------------------------------------------------------------------- *
 * Convex
 *
 * Convex has an authorization shape that no other framework in this engine shares,
 * and getting it wrong in either direction is expensive.
 *
 * **A `query` or a `mutation` is a public endpoint.** Any client that knows the
 * module path and the export name can call it — there is no router, no middleware
 * and no route file to gate it. `internalQuery`, `internalMutation` and
 * `internalAction` are the ones that are *not* reachable from a client. So the
 * distinction the engine has to carry is not "is this an entry point" but "is this
 * one the world can call", and it is spelled by the wrapper function rather than by
 * anything about the handler.
 *
 * **The caller's data arrives as the second argument.** `handler: async (ctx, args)`
 * — `args` is whatever the client sent, validated against the `args` validator if
 * one is declared. `ctx` is the framework's: `ctx.db`, `ctx.auth`, `ctx.storage`,
 * `ctx.runMutation`. Seeding `ctx` would be a disaster, because `ctx.auth.getUserIdentity()`
 * is the authenticated subject and every correctly written Convex function filters
 * by it.
 *
 * The address is the module path plus the export name, which is genuinely how a
 * Convex function is called — `api.documents.rename`. There is no URL to report and
 * inventing one would send a reader looking for an endpoint that does not exist.
 * ------------------------------------------------------------------------- */

const FRAMEWORK = "convex";

/** Wrappers a client can call directly. */
const PUBLIC_WRAPPERS = new Set(["query", "mutation", "action"]);

/** Wrappers only another Convex function can call. */
const INTERNAL_WRAPPERS = new Set(["internalQuery", "internalMutation", "internalAction"]);

/** An HTTP endpoint declared through the router rather than the function API. */
const HTTP_WRAPPER = "httpAction";

function boundNames(name: ts.BindingName): string[] {
  if (ts.isIdentifier(name)) return [name.text];
  const names: string[] = [];
  for (const element of name.elements) {
    if (ts.isOmittedExpression(element)) continue;
    names.push(...boundNames(element.name));
  }
  return names;
}

/** The `handler:` property of a Convex function definition object. */
function handlerOf(call: ts.CallExpression): ts.Node | undefined {
  const first = call.arguments[0];
  if (!first) return undefined;
  // `mutation(async (ctx, args) => …)` — the bare form, no validators.
  const direct = functionOf(first);
  if (direct) return direct;
  if (!ts.isObjectLiteralExpression(first)) return undefined;
  for (const property of first.properties) {
    if (!ts.isPropertyAssignment(property) && !ts.isMethodDeclaration(property)) continue;
    if (!ts.isIdentifier(property.name) || property.name.text !== "handler") continue;
    return ts.isMethodDeclaration(property) ? property : functionOf(property.initializer);
  }
  return undefined;
}

/**
 * Seeds and trusted parameters for a `(ctx, args)` handler.
 *
 * Position decides this, not name: the first parameter is the framework's context
 * whatever it is called, and the second is the client's payload whatever it is
 * called. A destructured `{ db, auth }` in slot one is still the context.
 */
function bindings(handler: ts.Node | undefined): { seeds: TaintSeed[]; trusted: string[] } {
  const parameters = (handler as ts.FunctionLikeDeclaration | undefined)?.parameters ?? [];
  const seeds: TaintSeed[] = [];
  const trusted: string[] = [];

  const context = parameters[0];
  if (context) trusted.push(...boundNames(context.name));

  const args = parameters[1];
  if (args) {
    for (const name of boundNames(args.name)) {
      seeds.push({ name, origin: "a Convex function argument (whatever the client sent)" });
    }
  }
  return { seeds, trusted };
}

/** `export const renameDocument = mutation({...})` gives the callable name. */
function exportedName(call: ts.CallExpression): string | null {
  let node: ts.Node = call;
  for (let depth = 0; node.parent && depth < 6; depth += 1) {
    const parent: ts.Node = node.parent;
    if (ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) return parent.name.text;
    node = parent;
  }
  return null;
}

/**
 * The module path a client addresses this through.
 *
 * `convex/documents.ts` is called as `api.documents.rename`, so the directory prefix
 * and the extension are both noise. A file under `convex/_lib/` is a helper and is
 * not addressable at all.
 */
function moduleAddress(file: ParsedFile, exportName: string | null): string {
  const relative = file.relativePath.replace(/\\/g, "/");
  const match = /(?:^|\/)convex\/(.+)\.[cm]?[jt]sx?$/.exec(relative);
  const module = match?.[1] ?? relative.replace(/\.[cm]?[jt]sx?$/, "");
  return exportName ? `${module}.${exportName}` : module;
}

export const convexAdapter: FrameworkAdapter = {
  id: FRAMEWORK,
  applies: (file) => importsFrom(file, /^convex\//) || /_generated\/server|convex\/values/.test(file.text),
  detect(file: ParsedFile): EntryPoint[] {
    const found: EntryPoint[] = [];

    for (const call of collect(file.source, ts.isCallExpression)) {
      const name = calleeName(call);
      const wrapper = name.includes(".") ? (name.split(".").pop() ?? name) : name;

      if (wrapper === HTTP_WRAPPER) {
        const handler = handlerOf(call);
        if (!handler) continue;
        /*
         * An `httpAction` handler is `(ctx, request)` — a real `Request`, so slot two
         * is the caller's for a different reason than above, and the generic model
         * would have found it anyway. Claimed so the address is right.
         */
        const parameters = (handler as ts.FunctionLikeDeclaration).parameters ?? [];
        const context = parameters[0];
        const request = parameters[1];
        found.push({
          framework: FRAMEWORK,
          kind: "http",
          method: "ANY",
          path: httpRouteFor(file, call) ?? moduleAddress(file, exportedName(call)),
          line: lineOf(file, call),
          node: handler,
          ...(request
            ? { seeds: boundNames(request.name).map((bound) => ({ name: bound, origin: "an inbound HTTP request to a Convex httpAction" })) }
            : {}),
          ...(context ? { trustedParameters: boundNames(context.name) } : {})
        });
        continue;
      }

      const isPublic = PUBLIC_WRAPPERS.has(wrapper);
      const isInternal = INTERNAL_WRAPPERS.has(wrapper);
      if (!isPublic && !isInternal) continue;

      const handler = handlerOf(call);
      if (!handler) continue;
      const { seeds, trusted } = bindings(handler);

      /*
       * An internal function is still an entry point — its arguments come from
       * another function that may itself be public, and a rule that needs to see the
       * flow needs the seed. What it is *not* is client-reachable, which is why the
       * kind differs: an authorization rule can then treat a missing identity check
       * in a `mutation` as a finding and the same code in an `internalMutation` as
       * ordinary internal plumbing.
       */
      found.push({
        framework: FRAMEWORK,
        kind: isPublic ? "rpc" : "queue",
        method: isPublic ? "INVOKE" : "CONSUME",
        path: moduleAddress(file, exportedName(call)),
        line: lineOf(file, call),
        node: handler,
        ...(seeds.length > 0 ? { seeds } : {}),
        ...(trusted.length > 0 ? { trustedParameters: trusted } : {})
      });
    }

    return found;
  }
};

/**
 * The path an `httpAction` is mounted at, when `convex/http.ts` is in the same file.
 *
 * Only when it is literally here. A route declared in another module is exactly the
 * case this engine declines to guess at.
 */
function httpRouteFor(file: ParsedFile, action: ts.CallExpression): string | null {
  const name = exportedName(action);
  if (!name) return null;
  for (const call of collect(file.source, ts.isCallExpression)) {
    if (calleeName(call).split(".").pop() !== "route") continue;
    const options = call.arguments[0];
    if (!options || !ts.isObjectLiteralExpression(options)) continue;
    let path: string | null = null;
    let method: string | null = null;
    let matches = false;
    for (const property of options.properties) {
      if (!ts.isPropertyAssignment(property) || !ts.isIdentifier(property.name)) continue;
      if (property.name.text === "path") path = literalTextOf(property.initializer);
      if (property.name.text === "method") method = literalTextOf(property.initializer);
      if (property.name.text === "handler" && property.initializer.getText().includes(name)) matches = true;
    }
    if (matches && path) return method ? `${method} ${path}` : path;
  }
  return null;
}
