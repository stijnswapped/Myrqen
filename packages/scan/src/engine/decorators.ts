/**
 * Parameter decorators that hand a method caller data, wherever the method is.
 *
 * The NestJS adapter (`ast/frameworks/nest.ts`) seeds a controller method that carries a
 * verb decorator, because that is a route it can name. The same parameter decorators bind
 * caller data in places that have no verb: a GraphQL resolver's `@Args('id')`, a WebSocket
 * gateway's `@MessageBody()`, a tsoa controller's `@Path()`, a type-graphql `@Arg()`. To the
 * taint model each is an ordinary typed parameter, so a sink fed by one was invisible.
 *
 * The rule here is provenance, not spelling. A decorator counts only when the file imports
 * it from the framework that defines it, by name or through a namespace import. `@Body` is
 * a common word and a project's own `@Path()` or `@CurrentUser()` says nothing about where
 * its value came from; reading either as caller data would produce one invented finding per
 * rule that reads the binding.
 *
 * The vocabulary was taken from each framework's own documentation. Frameworks used by the
 * held-out corpora (see `docs/12-release/HOLDOUT-PROTOCOL.md`) are deliberately absent, so
 * that no held-out figure moves because of an adapter written for it.
 */
import ts from "typescript";
import type { ParsedFile } from "../ast/parse.js";

const ROUTE = "caller-controlled route parameter";
const QUERY = "caller-controlled query string";
const BODY = "caller-controlled request body";
const HEADER = "caller-controlled request header";
const COOKIE = "caller-controlled cookie";
const UPLOAD = "caller-controlled file upload";
const REQUEST = "inbound request";
const GRAPHQL = "caller-controlled GraphQL argument";
const MESSAGE = "caller-controlled WebSocket message";

/** Per framework: the modules that export its decorators, and what each parameter decorator binds. */
const VOCABULARIES: ReadonlyArray<{ modules: RegExp; decorators: ReadonlyMap<string, string> }> = [
  {
    // NestJS and Midway share the vocabulary.
    modules: /^(@nestjs\/common|@midwayjs\/core|@midwayjs\/decorator)$/,
    decorators: new Map([
      ["Param", ROUTE],
      ["Query", QUERY],
      ["Queries", QUERY],
      ["Body", BODY],
      ["Headers", HEADER],
      ["UploadedFile", UPLOAD],
      ["UploadedFiles", UPLOAD],
      ["Req", REQUEST],
      ["Request", REQUEST],
      ["Ip", "caller-influenced client address"],
      ["HostParam", "caller-influenced host segment"]
    ])
  },
  { modules: /^@nestjs\/graphql$/, decorators: new Map([["Args", GRAPHQL]]) },
  { modules: /^type-graphql$/, decorators: new Map([["Arg", GRAPHQL], ["Args", GRAPHQL]]) },
  { modules: /^@nestjs\/websockets$/, decorators: new Map([["MessageBody", MESSAGE]]) },
  {
    modules: /^routing-controllers$/,
    decorators: new Map([
      ["Param", ROUTE],
      ["Params", ROUTE],
      ["QueryParam", QUERY],
      ["QueryParams", QUERY],
      ["Body", BODY],
      ["BodyParam", BODY],
      ["HeaderParam", HEADER],
      ["HeaderParams", HEADER],
      ["CookieParam", COOKIE],
      ["CookieParams", COOKIE],
      ["UploadedFile", UPLOAD],
      ["UploadedFiles", UPLOAD],
      ["Req", REQUEST]
    ])
  },
  {
    modules: /^@tsed\/(common|platform-params|platform-http)$/,
    decorators: new Map([
      ["PathParams", ROUTE],
      ["RawPathParams", ROUTE],
      ["QueryParams", QUERY],
      ["RawQueryParams", QUERY],
      ["BodyParams", BODY],
      ["RawBodyParams", BODY],
      ["HeaderParams", HEADER],
      ["Cookies", COOKIE],
      ["Req", REQUEST]
    ])
  },
  {
    modules: /^tsoa$/,
    decorators: new Map([
      ["Path", ROUTE],
      ["Query", QUERY],
      ["Queries", QUERY],
      ["Body", BODY],
      ["BodyProp", BODY],
      ["FormField", BODY],
      ["Header", HEADER],
      ["UploadedFile", UPLOAD],
      ["UploadedFiles", UPLOAD],
      ["Request", REQUEST]
    ])
  },
  {
    modules: /^inversify-express-utils$/,
    decorators: new Map([
      ["requestParam", ROUTE],
      ["queryParam", QUERY],
      ["requestBody", BODY],
      ["requestHeaders", HEADER],
      ["cookies", COOKIE],
      ["request", REQUEST]
    ])
  }
];

const ANY_MODULE = new RegExp(VOCABULARIES.map((vocabulary) => vocabulary.modules.source).join("|"));
/** The same module names, unanchored, as a cheap test of a file's text. */
const MENTIONS_MODULE = new RegExp(VOCABULARIES.map((vocabulary) => vocabulary.modules.source.replace(/^\^|\$$/g, "")).join("|"));

/** `local name → module` for every named or default import, and `namespace → module`. */
function importsOf(file: ParsedFile): { named: Map<string, { module: string; imported: string }>; namespaces: Map<string, string> } {
  const named = new Map<string, { module: string; imported: string }>();
  const namespaces = new Map<string, string>();
  for (const statement of file.source.statements) {
    if (!ts.isImportDeclaration(statement) || !ts.isStringLiteralLike(statement.moduleSpecifier)) continue;
    const module = statement.moduleSpecifier.text;
    if (!ANY_MODULE.test(module)) continue;
    const bindings = statement.importClause?.namedBindings;
    if (bindings && ts.isNamespaceImport(bindings)) namespaces.set(bindings.name.text, module);
    if (bindings && ts.isNamedImports(bindings)) {
      for (const element of bindings.elements) {
        named.set(element.name.text, { module, imported: element.propertyName?.text ?? element.name.text });
      }
    }
  }
  return { named, namespaces };
}

function describe(module: string, imported: string): string | undefined {
  for (const vocabulary of VOCABULARIES) {
    if (vocabulary.modules.test(module)) {
      const description = vocabulary.decorators.get(imported);
      if (description) return description;
    }
  }
  return undefined;
}

function literalArgument(call: ts.CallExpression): string {
  const first = call.arguments[0];
  return first && ts.isStringLiteralLike(first) ? `'${first.text}'` : "";
}

/**
 * Every method or function in this file with a parameter bound by a framework's request
 * decorator: `function node → parameter index → origin`.
 */
export function decoratedParameterSeeds(file: ParsedFile): Map<ts.Node, Map<number, string>> {
  const seeds = new Map<ts.Node, Map<number, string>>();
  if (!file.text.includes("@") || !MENTIONS_MODULE.test(file.text)) return seeds;
  const { named, namespaces } = importsOf(file);
  if (named.size === 0 && namespaces.size === 0) return seeds;

  const originOf = (decorator: ts.Decorator): string | null => {
    const expression = decorator.expression;
    if (!ts.isCallExpression(expression)) return null;
    const callee = expression.expression;
    let module: string | undefined;
    let imported: string | undefined;
    let written: string | undefined;
    if (ts.isIdentifier(callee)) {
      const entry = named.get(callee.text);
      module = entry?.module;
      imported = entry?.imported;
      written = callee.text;
    } else if (ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.expression)) {
      module = namespaces.get(callee.expression.text);
      imported = callee.name.text;
      written = callee.getText(file.source);
    }
    if (!module || !imported || !written) return null;
    const description = describe(module, imported);
    return description ? `@${written}(${literalArgument(expression)}) (${description})` : null;
  };

  const visit = (node: ts.Node): void => {
    // Not a constructor: a decorated constructor parameter is dependency injection.
    if (ts.isFunctionLike(node) && !ts.isConstructorDeclaration(node)) {
      const parameters = (node as ts.FunctionLikeDeclaration).parameters ?? [];
      parameters.forEach((parameter, index) => {
        const decorators = (ts.canHaveDecorators(parameter) ? ts.getDecorators(parameter) : undefined) ?? [];
        for (const decorator of decorators) {
          const origin = originOf(decorator);
          if (!origin) continue;
          const byIndex = seeds.get(node) ?? new Map<number, string>();
          if (!byIndex.has(index)) byIndex.set(index, origin);
          seeds.set(node, byIndex);
        }
      });
    }
    node.forEachChild(visit);
  };
  visit(file.source);
  return seeds;
}
