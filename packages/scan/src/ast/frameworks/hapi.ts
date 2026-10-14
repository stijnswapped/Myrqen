import ts from "typescript";
import { functionOf, importsFrom, type EntryPoint, type FrameworkAdapter } from "../entrypoints.js";
import { calleeName, collect, literalTextOf } from "../helpers.js";
import { lineOf, type ParsedFile } from "../parse.js";

/* ------------------------------------------------------------------------- *
 * Hapi 17-21
 *
 * The input side of Hapi needs almost nothing from an adapter: a handler is
 * `(request, h)` and the generic model already treats a parameter named `request`
 * as the caller's. What it needs is the two things that model cannot supply.
 *
 * The **address**. Hapi declares a route as a configuration object —
 * `server.route({ method: 'GET', path: '/api/notes/{noteId}', handler })` — and the
 * handler is a property of that object rather than an argument following the path.
 * Nothing in the generic registration model matches that shape, so every finding in
 * a Hapi application was reported against no endpoint at all.
 *
 * The **prerequisites**. `options.pre` is a list of functions that run before the
 * handler and, in real Hapi code, is where the record gets loaded — which means it
 * is where the missing ownership predicate lives. Each one is a handler in its own
 * right with the same `(request, h)` signature, and an adapter that claimed only the
 * `handler` property would leave the most interesting function in the file
 * unattributed.
 *
 * Path parameters are reported the way Hapi spells them, `{noteId}`, because that is
 * what the file says and translating it into somebody else's convention would make
 * the address ungreppable.
 * ------------------------------------------------------------------------- */

const FRAMEWORK = "hapi";

const METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "*"]);

/** The `method` of a route object: a literal, an array of them, or `*`. */
function methodOf(options: ts.ObjectLiteralExpression): string {
  const property = propertyNamed(options, "method");
  if (!property) return "ANY";
  const single = literalTextOf(property);
  if (single) {
    const upper = single.toUpperCase();
    return upper === "*" ? "ANY" : METHODS.has(upper) ? upper : "ANY";
  }
  if (ts.isArrayLiteralExpression(property)) {
    // Several verbs, one handler. `ANY` is the honest label — naming the first
    // would tell a reader to probe one address and miss the others.
    const verbs = property.elements.map((element) => literalTextOf(element)).filter((value): value is string => Boolean(value));
    if (verbs.length === 1) return verbs[0]!.toUpperCase();
    return "ANY";
  }
  return "ANY";
}

function propertyNamed(object: ts.ObjectLiteralExpression, name: string): ts.Expression | undefined {
  for (const property of object.properties) {
    if (ts.isPropertyAssignment(property) && ts.isIdentifier(property.name) && property.name.text === name) {
      return property.initializer;
    }
    if (ts.isShorthandPropertyAssignment(property) && property.name.text === name) return property.name;
  }
  return undefined;
}

/** A `handler` or a method-shaped property, wherever Hapi allows one. */
function handlerIn(object: ts.ObjectLiteralExpression, name: string): ts.Node | undefined {
  for (const property of object.properties) {
    if (ts.isMethodDeclaration(property) && ts.isIdentifier(property.name) && property.name.text === name) return property;
    if (!ts.isPropertyAssignment(property) || !ts.isIdentifier(property.name)) continue;
    if (property.name.text !== name) continue;
    return functionOf(property.initializer);
  }
  return undefined;
}

/**
 * Every function a route object runs, with what to call it.
 *
 * The prerequisite label carries its `assign` key when it has one, because that is
 * how a Hapi developer refers to it — `pre.note` — and a bare index would not tell
 * a reader which of four prerequisites the finding is in.
 */
function handlersOf(options: ts.ObjectLiteralExpression): Array<{ node: ts.Node; label: string | null }> {
  const found: Array<{ node: ts.Node; label: string | null }> = [];

  const direct = handlerIn(options, "handler");
  if (direct) found.push({ node: direct, label: null });

  const nested = propertyNamed(options, "options");
  const config = nested && ts.isObjectLiteralExpression(nested) ? nested : options;
  if (config !== options) {
    const inner = handlerIn(config, "handler");
    if (inner) found.push({ node: inner, label: null });
  }

  const pre = propertyNamed(config, "pre");
  if (pre && ts.isArrayLiteralExpression(pre)) {
    for (const element of pre.elements) {
      if (ts.isObjectLiteralExpression(element)) {
        const method = handlerIn(element, "method");
        if (!method) continue;
        const assign = propertyNamed(element, "assign");
        const key = assign ? literalTextOf(assign) : null;
        found.push({ node: method, label: key ? `pre.${key}` : "pre" });
        continue;
      }
      const bare = functionOf(element);
      if (bare) found.push({ node: bare, label: "pre" });
    }
  }
  return found;
}

export const hapiAdapter: FrameworkAdapter = {
  id: FRAMEWORK,
  applies: (file) => importsFrom(file, /^@hapi\//) || /\bserver\.route\s*\(/.test(file.text),
  detect(file: ParsedFile): EntryPoint[] {
    const found: EntryPoint[] = [];

    for (const call of collect(file.source, ts.isCallExpression)) {
      if (calleeName(call).split(".").pop() !== "route") continue;
      const argument = call.arguments[0];
      if (!argument) continue;

      // `server.route({...})` and `server.route([{...}, {...}])` are both idiomatic.
      const objects = ts.isArrayLiteralExpression(argument)
        ? argument.elements.filter(ts.isObjectLiteralExpression)
        : ts.isObjectLiteralExpression(argument)
          ? [argument]
          : [];

      for (const options of objects) {
        const pathProperty = propertyNamed(options, "path");
        const routePath = pathProperty ? literalTextOf(pathProperty) : null;
        // Without a literal path this is not a Hapi route object we can address, and
        // claiming it would attach findings to an address we invented.
        if (!routePath || !routePath.startsWith("/")) continue;
        const method = methodOf(options);

        for (const { node, label } of handlersOf(options)) {
          found.push({
            framework: FRAMEWORK,
            kind: "http",
            method,
            path: label ? `${routePath} (${label})` : routePath,
            line: lineOf(file, node),
            node,
            /*
             * `h` is the response toolkit — the way a handler *replies*. Naming it
             * trusted matters because a single-letter parameter is exactly the kind
             * of thing a generic model might take for caller data, and every finding
             * it invented would be in correct code.
             */
            trustedParameters: responseToolkitNames(node)
          });
        }
      }
    }

    return found;
  }
};

/** Every parameter after the request: the response toolkit, and in a `pre`, nothing else. */
function responseToolkitNames(handler: ts.Node): string[] {
  const parameters = (handler as ts.FunctionLikeDeclaration).parameters ?? [];
  return parameters
    .slice(1)
    .map((parameter) => (ts.isIdentifier(parameter.name) ? parameter.name.text : null))
    .filter((name): name is string => Boolean(name));
}
