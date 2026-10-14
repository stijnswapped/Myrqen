import ts from "typescript";
import { importsFrom, joinRoute, type EntryPoint, type FrameworkAdapter, type TaintSeed } from "../entrypoints.js";
import { collect, literalTextOf } from "../helpers.js";
import { lineOf, type ParsedFile } from "../parse.js";

/*
 * NestJS, and the decorator-based frameworks that copied its shape.
 *
 * A controller registers nothing this analyser can watch for. There is no
 * `app.get("/x", handler)` anywhere in the file: the address lives in a class
 * decorator joined to a method decorator, and the framework does the wiring at
 * runtime through metadata the parser never sees.
 *
 * The seeds matter more than the address. Nest hands the caller's data over as
 * parameters, so `findOne(@Param('id') id: string)` is, to any model that looks
 * for a binding named `req`, a handler with no request in it at all — an
 * ordinary string argument that happens to be whatever the caller put in the
 * URL. Without this adapter naming `id`, a controller that interpolates it into
 * a query is a file in which every data-flow rule is correct and silent.
 *
 * The same reasoning runs the other way for `@Res()` and `@Session()`. Both are
 * parameters, both look like handler input, and neither carries anything the
 * caller chose. Declaring them trusted is what stops the seeds above from
 * turning into a second, invented class of finding.
 */

const ADAPTER_ID = "nest";

/**
 * Packages whose decorator vocabulary means HTTP. `@Get` is a common word — ORMs,
 * dependency-injection containers and hand-written aspects all decorate methods
 * with it — so outside a class that says `@Controller` it only counts as a route
 * when one of these frameworks is actually imported.
 */
const FRAMEWORK_MODULE = /@nestjs\/|@foal|routing-controllers|tsed/;

/** Class decorators that make the class a controller, whatever the file imports. */
const CONTROLLER_DECORATORS = new Set(["Controller", "JsonController"]);

/**
 * Method decorators that publish the method at a URL, and the verb each means.
 *
 * `@All()` answers every verb, which the report writes as `ANY` the way the
 * Express-style discovery already writes `app.use`. `@Sse()` is a GET that never
 * closes; the streaming is irrelevant here, reachability is not.
 */
const VERB_DECORATORS = new Map<string, string>([
  ["Get", "GET"],
  ["Post", "POST"],
  ["Put", "PUT"],
  ["Patch", "PATCH"],
  ["Delete", "DELETE"],
  ["Options", "OPTIONS"],
  ["Head", "HEAD"],
  ["All", "ANY"],
  ["Sse", "GET"]
]);

/**
 * Parameter decorators that bind data the caller chose, with the words used
 * verbatim in evidence.
 *
 * The aliases are the same three concepts under the neighbouring frameworks'
 * spelling — routing-controllers writes `@QueryParam('q')`, Ts.ED writes
 * `@PathParams('id')` — and they mean exactly what the Nest names mean. Nothing
 * ambiguous is listed: a decorator whose value might be server-derived belongs
 * in the trusted set or in neither, never here, because a wrong seed does not
 * produce one bad finding, it produces one per rule that reads the binding.
 *
 * Nest's `@Header('Cache-Control', 'none')` is deliberately absent. It sets a
 * *response* header and is a method decorator; the request-side decorator is the
 * plural `@Headers`, and confusing the two would seed a value the caller never
 * sent.
 */
const SEED_DECORATORS = new Map<string, string>([
  ["Param", "caller-controlled route parameter"],
  ["Params", "caller-controlled route parameter"],
  ["PathParams", "caller-controlled route parameter"],
  ["Query", "caller-controlled query string"],
  ["QueryParam", "caller-controlled query string"],
  ["QueryParams", "caller-controlled query string"],
  ["Body", "caller-controlled request body"],
  ["BodyParam", "caller-controlled request body"],
  ["BodyParams", "caller-controlled request body"],
  ["RawBody", "caller-controlled request body"],
  ["Headers", "caller-controlled request header"],
  ["HeaderParam", "caller-controlled request header"],
  ["HeaderParams", "caller-controlled request header"],
  ["UploadedFile", "caller-controlled file upload"],
  ["UploadedFiles", "caller-controlled file upload"],
  ["Req", "inbound request"],
  ["Request", "inbound request"],
  // Both are read from headers the moment a proxy sits in front of the app, so
  // they are attacker-influenced rather than attacker-authored. Influence is
  // enough: a host segment reaching a redirect or a query is the whole defect.
  ["Ip", "caller-influenced client address"],
  ["HostParam", "caller-influenced host segment"]
]);

/**
 * Parameters the caller did not fill in.
 *
 * A session is server-derived — the caller supplies a cookie, the framework
 * supplies the contents — and a response object is an output, not an input.
 * Both sit in the parameter list beside genuine seeds, and a model that reads
 * parameter names would happily call `session` user input.
 */
const TRUSTED_DECORATORS = new Set(["Res", "Response", "Session", "Next"]);

/** Any decorator in the vocabulary, written as the factory call all four frameworks require. */
const DECORATOR_CALL = /@(?:Controller|JsonController|Get|Post|Put|Patch|Delete|Options|Head|All|Sse)\s*\(/;
const CONTROLLER_CALL = /@(?:Controller|JsonController)\s*\(/;

export const nestAdapter: FrameworkAdapter = {
  id: ADAPTER_ID,
  applies(file: ParsedFile): boolean {
    if (!DECORATOR_CALL.test(file.text)) return false;
    // A controller decorator is self-identifying. A verb decorator on its own is
    // not, so the file has to name one of the frameworks somewhere before this
    // adapter is willing to walk it.
    return CONTROLLER_CALL.test(file.text) || FRAMEWORK_MODULE.test(file.text);
  },
  detect(file: ParsedFile): EntryPoint[] {
    const fromFramework = importsFrom(file, FRAMEWORK_MODULE);
    const entries: EntryPoint[] = [];

    for (const declaration of collect(file.source, ts.isClassLike)) {
      const controller = decoratorsOf(declaration).find((decorator) =>
        CONTROLLER_DECORATORS.has(decoratorName(decorator))
      );
      // Foal puts its routes on an undecorated class and relies on the module
      // that mounts it, so a real import from a known framework is enough on its
      // own. With neither the decorator nor the import there is nothing tying
      // `@Get` to HTTP, and guessing would invent an endpoint.
      if (!controller && !fromFramework) continue;

      const base = controller ? pathArgumentOf(controller) : null;

      for (const member of declaration.members) {
        if (!ts.isMethodDeclaration(member)) continue;
        const verbs = decoratorsOf(member).filter((decorator) => VERB_DECORATORS.has(decoratorName(decorator)));
        if (verbs.length === 0) continue;

        const bindings = bindingsOf(member);
        // Reported at the decorator rather than at the method: the decorator is
        // the line a reader searches for when they want to find the route, and
        // it is where the address is actually written.
        const line = lineOf(file, verbs[0] ?? member);

        // Stacked verbs (`@Get() @Post() save()`) are two addresses reaching one
        // body. Each is emitted, because a report that names only the first
        // tells the reader to test half of what is exposed.
        for (const verb of verbs) {
          entries.push({
            framework: ADAPTER_ID,
            kind: "http",
            method: VERB_DECORATORS.get(decoratorName(verb)) ?? "ANY",
            path: joinRoute(base, pathArgumentOf(verb)),
            line,
            node: member,
            ...(bindings.seeds.length > 0 ? { seeds: bindings.seeds } : {}),
            ...(bindings.trusted.length > 0 ? { trustedParameters: bindings.trusted } : {})
          });
        }
      }
    }

    return entries;
  }
};

/* ---------- decorators ---------- */

function decoratorsOf(node: ts.Node): readonly ts.Decorator[] {
  return (ts.canHaveDecorators(node) ? ts.getDecorators(node) : undefined) ?? [];
}

/** `@Get(':id')` and `@common.Get(':id')` are the same decorator under a namespace import. */
function decoratorName(decorator: ts.Decorator): string {
  const expression = ts.isCallExpression(decorator.expression) ? decorator.expression.expression : decorator.expression;
  if (ts.isIdentifier(expression)) return expression.text;
  if (ts.isPropertyAccessExpression(expression)) return expression.name.text;
  return "";
}

function decoratorArguments(decorator: ts.Decorator): readonly ts.Expression[] {
  return ts.isCallExpression(decorator.expression) ? decorator.expression.arguments : [];
}

/**
 * The path a controller or verb decorator declares, in Nest's own `:id` syntax.
 *
 * Rewriting the parameter syntax would be a mistake here: `:id` is what the file
 * says, what the developer greps for, and what they type into a request when
 * they go to reproduce a finding.
 */
function pathArgumentOf(decorator: ts.Decorator): string | null {
  const first = decoratorArguments(decorator)[0];
  if (!first) return null;
  if (ts.isObjectLiteralExpression(first)) return optionPath(first);
  return firstLiteral(first);
}

/**
 * `@Controller({ path: 'invoices', version: '1' })`.
 *
 * The version is read and dropped. Whether it becomes a `/v1` prefix, a header
 * or a media type is decided by an application-wide setting that lives in a
 * different file, so writing `/v1/invoices` here would be a guess that mislabels
 * every route in a project versioned by header.
 */
function optionPath(options: ts.ObjectLiteralExpression): string | null {
  for (const property of options.properties) {
    if (!ts.isPropertyAssignment(property)) continue;
    const name = ts.isIdentifier(property.name) || ts.isStringLiteralLike(property.name) ? property.name.text : "";
    if (name !== "path") continue;
    return firstLiteral(property.initializer);
  }
  return null;
}

/**
 * A string literal, or the first of a list of them.
 *
 * `@Controller(['cats', 'kittens'])` gives one handler several addresses. Only
 * the first is reported: the aliases run the same body, and an entry point per
 * alias would repeat every finding in that body once per name.
 */
function firstLiteral(expression: ts.Expression): string | null {
  const literal = literalTextOf(expression);
  if (literal !== null) return literal;
  if (ts.isArrayLiteralExpression(expression)) {
    for (const element of expression.elements) {
      const alias = literalTextOf(element);
      if (alias !== null) return alias;
    }
  }
  // A path held in a constant leaves the address partly unknown. The entry point
  // is still emitted from whatever the other half declares, because a route
  // reported under an incomplete path is recoverable and a handler with no entry
  // point at all is invisible.
  return null;
}

/* ---------- seeds ---------- */

interface HandlerBindings {
  seeds: TaintSeed[];
  trusted: string[];
}

function bindingsOf(method: ts.MethodDeclaration): HandlerBindings {
  const seeds = new Map<string, TaintSeed>();
  const trusted = new Set<string>();

  for (const parameter of method.parameters) {
    for (const decorator of decoratorsOf(parameter)) {
      const name = decoratorName(decorator);

      if (TRUSTED_DECORATORS.has(name)) {
        for (const bound of boundNames(parameter.name)) trusted.add(bound);
        continue;
      }

      const description = SEED_DECORATORS.get(name);
      // An unrecognised decorator is left alone on purpose. A project's own
      // `@CurrentUser()` or `@Tenant()` says nothing about where its value came
      // from, and both answers — trusted or tainted — would be invented.
      if (description === undefined) continue;

      const origin = `@${name}(${quotedArgument(decorator)}) (${description})`;
      for (const bound of boundNames(parameter.name)) {
        if (!seeds.has(bound)) seeds.set(bound, { name: bound, origin });
      }
    }
  }

  return { seeds: [...seeds.values()], trusted: [...trusted] };
}

/**
 * The selector a parameter decorator names, rendered back as source.
 *
 * Only a literal is kept, so `@Body(new ValidationPipe())` reads as `@Body()`
 * rather than quoting a pipe the reader would have to decode.
 */
function quotedArgument(decorator: ts.Decorator): string {
  const first = decoratorArguments(decorator)[0];
  const literal = first ? literalTextOf(first) : null;
  return literal === null ? "" : `'${literal}'`;
}

/**
 * Every local name a parameter introduces.
 *
 * `@Body() { name, price }` binds two names and the parameter itself has none,
 * so seeding the parameter would seed nothing and both fields would flow through
 * the handler untracked. Renames and rest elements bind under their new names,
 * which is what the body of the method actually reads.
 */
function boundNames(name: ts.BindingName): string[] {
  if (ts.isIdentifier(name)) return [name.text];
  const elements: readonly ts.Node[] = name.elements;
  return elements.flatMap((element) => (ts.isBindingElement(element) ? boundNames(element.name) : []));
}
