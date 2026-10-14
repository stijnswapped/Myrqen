import ts from "typescript";
import { importsFrom, parameterNames, type EntryPoint, type FrameworkAdapter, type TaintSeed } from "../entrypoints.js";
import { collect } from "../helpers.js";
import { lineOf, type ParsedFile } from "../parse.js";

/* ------------------------------------------------------------------------- *
 * AdonisJS v6
 *
 * Adonis puts the handler and its address in different files, on purpose. A
 * controller method is an ordinary class method taking one `HttpContext`, and the
 * URL that reaches it lives in `start/routes.ts` as
 * `router.get('/api/invoices/:id', [InvoicesController, 'show'])`. Reading the
 * controller alone therefore yields a method with no address and — worse — no
 * reason to believe its parameter holds anything a caller chose.
 *
 * The generic model does recognise a parameter *named* `ctx`, but almost nobody
 * writes Adonis that way: the idiom is to destructure the context in the signature,
 * `async show({ request, params, auth, response }: HttpContext)`, which leaves no
 * parameter named `ctx` anywhere. So the destructured bindings have to be named
 * explicitly, and — this is the half that matters for precision — the ones that are
 * *not* the caller's have to be named too. `auth.user.id` is the authenticated
 * subject, which is exactly the value a correctly scoped query filters by; seeding
 * it would make every properly written controller in an Adonis application look
 * broken.
 * ------------------------------------------------------------------------- */

const FRAMEWORK = "adonis";

/** Context bindings the caller fills in. */
const CALLER_BINDINGS = new Map<string, string>([
  ["request", "the Adonis request (query string, body, headers, route parameters)"],
  ["params", "an Adonis route parameter"]
]);

/**
 * Context bindings the framework establishes, which must never be seeded.
 *
 * `auth` carries the authenticated user; `response`, `view`, `logger` and `bouncer`
 * are outbound or server-side. `session` is Adonis's signed cookie session: a caller
 * can influence what was put into it earlier, but treating it as inbound request
 * data would disarm every ownership check written against it, which costs far more
 * than it finds.
 */
const TRUSTED_BINDINGS = ["auth", "response", "view", "logger", "bouncer", "session", "i18n", "ally", "route"];

function boundNames(name: ts.BindingName): string[] {
  if (ts.isIdentifier(name)) return [name.text];
  const names: string[] = [];
  for (const element of name.elements) {
    if (ts.isOmittedExpression(element)) continue;
    names.push(...boundNames(element.name));
  }
  return names;
}

/** Is this parameter an `HttpContext`, by annotation or by what it destructures? */
function contextParameter(parameter: ts.ParameterDeclaration | undefined): boolean {
  if (!parameter) return false;
  const annotation = parameter.type?.getText() ?? "";
  if (/\bHttpContext\b/.test(annotation)) return true;
  if (!ts.isObjectBindingPattern(parameter.name)) return false;
  // No annotation: the shape has to speak for itself. A destructured object that
  // names at least one caller binding *and* one framework binding is a context;
  // one that names only `request` could be anything.
  const bound = new Set(boundNames(parameter.name));
  const caller = [...CALLER_BINDINGS.keys()].some((name) => bound.has(name));
  const framework = TRUSTED_BINDINGS.some((name) => bound.has(name));
  return caller && framework;
}

function seedsAndTrusted(parameter: ts.ParameterDeclaration): { seeds: TaintSeed[]; trusted: string[] } {
  const seeds: TaintSeed[] = [];
  const trusted: string[] = [];
  if (ts.isIdentifier(parameter.name)) {
    // `async show(ctx: HttpContext)` — the whole context is the root, and the
    // generic model already treats `ctx` as a request. Nothing to add.
    return { seeds, trusted };
  }
  if (!ts.isObjectBindingPattern(parameter.name)) return { seeds, trusted };
  for (const element of parameter.name.elements) {
    if (!ts.isIdentifier(element.name)) {
      // `{ request: { all } }` — an unusual but legal shape. Seed every name it
      // introduces rather than guessing which one carries what.
      const source = element.propertyName && ts.isIdentifier(element.propertyName) ? element.propertyName.text : null;
      if (source && CALLER_BINDINGS.has(source)) {
        for (const bound of boundNames(element.name)) {
          seeds.push({ name: bound, origin: CALLER_BINDINGS.get(source) ?? "an Adonis request binding" });
        }
      }
      continue;
    }
    const source = element.propertyName && ts.isIdentifier(element.propertyName) ? element.propertyName.text : element.name.text;
    const origin = CALLER_BINDINGS.get(source);
    if (origin) seeds.push({ name: element.name.text, origin });
    else if (TRUSTED_BINDINGS.includes(source)) trusted.push(element.name.text);
  }
  return { seeds, trusted };
}

/**
 * The address, as far as the controller can know it.
 *
 * `ANY` and the controller's own name, because the verb and the path are declared in
 * `start/routes.ts` and this file genuinely cannot see them. Reporting a guessed path
 * would be worse than reporting an honest procedure name: the reader would go looking
 * for a URL that does not exist. Where the route file *is* in the scan,
 * `ast/route-index.ts` attributes the handler properly and this label is replaced.
 */
function controllerAddress(className: string | undefined, methodName: string): string {
  return className ? `${className}.${methodName}` : methodName;
}

export const adonisAdapter: FrameworkAdapter = {
  id: FRAMEWORK,
  applies: (file) =>
    importsFrom(file, /^@adonisjs\//) || /\bHttpContext\b/.test(file.text) || /@ioc:Adonis\//.test(file.text),
  detect(file: ParsedFile): EntryPoint[] {
    const found: EntryPoint[] = [];

    for (const declaration of collect(file.source, ts.isClassDeclaration)) {
      const className = declaration.name?.text;
      for (const member of declaration.members) {
        if (!ts.isMethodDeclaration(member) || !member.body) continue;
        if (!ts.isIdentifier(member.name)) continue;
        const first = member.parameters[0];
        if (!contextParameter(first) || !first) continue;
        const { seeds, trusted } = seedsAndTrusted(first);
        found.push({
          framework: FRAMEWORK,
          kind: "http",
          method: "ANY",
          path: controllerAddress(className, member.name.text),
          line: lineOf(file, member),
          node: member,
          ...(seeds.length > 0 ? { seeds } : {}),
          ...(trusted.length > 0 ? { trustedParameters: trusted } : {})
        });
      }
    }

    /*
     * A middleware class handles every request that passes through it, and its
     * `handle(ctx, next)` is where a header or a cookie is first read. Claimed for
     * the same reason a controller is: without it the file is invisible.
     */
    for (const declaration of collect(file.source, ts.isClassDeclaration)) {
      for (const member of declaration.members) {
        if (!ts.isMethodDeclaration(member) || !member.body) continue;
        if (!ts.isIdentifier(member.name) || member.name.text !== "handle") continue;
        if (found.some((entry) => entry.node === member)) continue;
        const first = member.parameters[0];
        if (!contextParameter(first) || !first) continue;
        const { seeds, trusted } = seedsAndTrusted(first);
        const names = parameterNames(member);
        found.push({
          framework: FRAMEWORK,
          kind: "http",
          method: "ANY",
          path: declaration.name?.text ?? "middleware",
          line: lineOf(file, member),
          node: member,
          ...(seeds.length > 0 ? { seeds } : {}),
          // `next` continues the pipeline; it is not the caller's.
          trustedParameters: [...trusted, ...names.slice(1).filter((name): name is string => Boolean(name))]
        });
      }
    }

    return found;
  }
};
