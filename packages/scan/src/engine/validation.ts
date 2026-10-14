/**
 * What a schema validator lets through: zod, yup, joi and valibot.
 *
 * A schema parse is the commonest validation in a TypeScript codebase, and the taint
 * model knew it two wrong ways at once. `Body.parse(req.body)` was an unknown function
 * handed caller data, so its result stayed tainted whatever the schema said — a
 * `z.string().uuid()` field interpolated into SQL was reported as injection. And
 * `if (!Body.safeParse(req.body).success) return` cleared the *whole request*, so a
 * `z.string()` field — which constrains nothing about its content — read as safe.
 *
 * The answer depends on the field, so this reads the schema:
 *
 *  - **constrained** — a number, a boolean, an enum or literal, a UUID/CUID/ULID, an ISO
 *    date, a string matched by an anchored pattern with no dangerous characters. Its value
 *    is one of a set the code chose, or cannot carry markup, a quote or a separator. The
 *    taint model clears it (numbers stay *value*-tainted, like `Number(x)`: the amount is
 *    still the caller's amount).
 *  - **open** — a string, an email, a URL, `any`, `unknown`, a record, a transform. It is
 *    still the caller's text, and stays tainted.
 *  - **object** — field by field.
 *
 * Only a schema this scan can read is interpreted; an imported schema is resolved through
 * the module graph by `scan`, and one it cannot resolve leaves the model's earlier
 * behaviour exactly as it was.
 */
import ts from "typescript";
import type { ParsedFile } from "../ast/parse.js";
import type { ModuleGraph } from "./modules.js";

export type SchemaShape =
  | { kind: "constrained"; numeric: boolean }
  | { kind: "open" }
  | { kind: "object"; fields: Map<string, SchemaShape> }
  | { kind: "array"; element: SchemaShape };

const OPEN: SchemaShape = { kind: "open" };

/** Builders whose result is constrained whatever is chained after them. */
const CONSTRAINED_ROOTS = new Map<string, boolean>([
  // name → numeric
  ["number", true],
  ["bigint", true],
  ["int", true],
  ["integer", true],
  ["boolean", false],
  ["bool", false],
  ["enum", false],
  ["nativeEnum", false],
  ["literal", false],
  ["picklist", false],
  ["date", false],
  ["isoDate", false],
  ["nan", true],
  ["null", false],
  ["undefined", false],
  ["void", false]
]);

/** String refinements that constrain the whole value to a safe alphabet. */
const CONSTRAINING_REFINEMENTS = new Set([
  "uuid",
  "guid",
  "cuid",
  "cuid2",
  "ulid",
  "nanoid",
  "datetime",
  "isoDate",
  "isoDateTime",
  "isoTimestamp",
  "date",
  "time",
  "ip",
  "ipv4",
  "ipv6",
  "alphanum",
  "hex",
  "base64",
  "creditCard",
  "isoDuration",
  "oneOf",
  "valid",
  "integer",
  "int",
  "positive",
  "negative",
  "port"
]);

/** Refinements that hand back a different value, so nothing earlier is known about it. */
const OPENING_REFINEMENTS = new Set(["transform", "preprocess", "custom", "any", "unknown", "passthrough", "catchall", "record"]);

/** Modifiers that change nothing about what the value may contain. */
const NEUTRAL = new Set([
  "optional",
  "nullable",
  "nullish",
  "default",
  "describe",
  "min",
  "max",
  "length",
  "nonempty",
  "trim",
  "toLowerCase",
  "toUpperCase",
  "lowercase",
  "uppercase",
  "required",
  "strict",
  "strip",
  "label",
  "meta",
  "openapi",
  "brand",
  "readonly",
  "catch",
  "refine",
  "superRefine",
  "check",
  "pipe",
  "messages",
  "error",
  "allow",
  "empty",
  "notRequired",
  "defined",
  "nonNullable",
  "shape",
  "strictObject",
  "looseObject",
  "positive",
  "finite",
  "safe",
  "multipleOf",
  "gt",
  "gte",
  "lt",
  "lte",
  "startsWith",
  "endsWith",
  "includes",
  "email"
]);

function unwrap(node: ts.Node): ts.Node {
  let current = node;
  for (let depth = 0; depth < 6; depth += 1) {
    if (
      ts.isParenthesizedExpression(current) ||
      ts.isAsExpression(current) ||
      ts.isSatisfiesExpression(current) ||
      ts.isNonNullExpression(current) ||
      ts.isAwaitExpression(current)
    ) {
      current = current.expression;
      continue;
    }
    return current;
  }
  return current;
}

/** An anchored pattern whose whole alphabet is free of quotes, separators and dots. */
function safePattern(node: ts.Node | undefined): boolean {
  if (!node) return false;
  const bare = unwrap(node);
  if (!ts.isRegularExpressionLiteral(bare)) return false;
  const body = /^\/(.*)\/[a-z]*$/s.exec(bare.text)?.[1];
  if (!body || !body.startsWith("^") || !body.endsWith("$")) return false;
  const inner = body.slice(1, -1);
  if (inner.includes("|")) return false;
  const stripped = inner.replace(/\\./g, "");
  return !/[.\/\\"'`;&$<>(){}\s%]/.test(stripped);
}

/** Resolves an identifier that names a schema, possibly in another module. */
export type SchemaResolver = (identifier: ts.Identifier) => ts.Expression | null;

/** Modules whose exports build schemas. */
const VALIDATION_MODULES = /^(zod|zod\/v[0-9]+|zod\/mini|yup|joi|@hapi\/joi|valibot)$/;
/** The conventional namespace names, honoured only when nothing local claims the name. */
const CONVENTIONAL_NAMESPACES = /^(z|zod|yup|Yup|Joi|joi|v|valibot|y)$/;

/** Where a name is bound at module scope: imported from a module, declared locally, or neither. */
function moduleBinding(identifier: ts.Identifier): { from: string } | "local" | null {
  const source = identifier.getSourceFile();
  const name = identifier.text;
  for (const statement of source.statements) {
    if (ts.isImportDeclaration(statement) && ts.isStringLiteralLike(statement.moduleSpecifier)) {
      const clause = statement.importClause;
      if (!clause) continue;
      const from = statement.moduleSpecifier.text;
      if (clause.name?.text === name) return { from };
      const bindings = clause.namedBindings;
      if (bindings && ts.isNamespaceImport(bindings) && bindings.name.text === name) return { from };
      if (bindings && ts.isNamedImports(bindings) && bindings.elements.some((element) => element.name.text === name)) return { from };
      continue;
    }
    if (ts.isVariableStatement(statement)) {
      for (const declaration of statement.declarationList.declarations) {
        const initializer = declaration.initializer ? unwrap(declaration.initializer) : undefined;
        const required =
          initializer && ts.isCallExpression(initializer) && ts.isIdentifier(initializer.expression) && initializer.expression.text === "require"
            ? initializer.arguments[0]
            : undefined;
        const binds = ts.isIdentifier(declaration.name)
          ? declaration.name.text === name
          : declaration.name.elements.some((element) => !ts.isOmittedExpression(element) && ts.isIdentifier(element.name) && element.name.text === name);
        if (!binds) continue;
        if (required && ts.isStringLiteralLike(required)) return { from: required.text };
        return "local";
      }
      continue;
    }
    if ((ts.isFunctionDeclaration(statement) || ts.isClassDeclaration(statement)) && statement.name?.text === name) return "local";
  }
  return null;
}

/**
 * Is this identifier a schema library's namespace (`z`, `yup`, `Joi`, `v`) or a builder
 * imported from one (`import { object, string } from "valibot"`)?
 *
 * A project's own object with a `number()` method and a `parse` on its result is not a
 * validator, and reading it as one would clear a value nothing constrained. So a name
 * counts when it was imported from a validation library, or when it has a conventional
 * namespace spelling and nothing in the module declares it as something else.
 */
function isLibraryName(identifier: ts.Identifier): boolean {
  const binding = moduleBinding(identifier);
  if (binding === "local") return false;
  if (binding) return VALIDATION_MODULES.test(binding.from);
  return CONVENTIONAL_NAMESPACES.test(identifier.text);
}

function localSchema(identifier: ts.Identifier): ts.Expression | null {
  const source = identifier.getSourceFile();
  for (const statement of source.statements) {
    if (!ts.isVariableStatement(statement)) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (ts.isIdentifier(declaration.name) && declaration.name.text === identifier.text && declaration.initializer) {
        return declaration.initializer;
      }
    }
  }
  return null;
}

/**
 * The shape a schema expression describes, or null when it is not a schema this reader
 * recognises (in which case nothing about the model changes).
 */
export function schemaShape(node: ts.Node, resolve: SchemaResolver = localSchema, depth = 0): SchemaShape | null {
  if (depth > 12) return null;
  const bare = unwrap(node);

  if (ts.isIdentifier(bare)) {
    const target = resolve(bare) ?? (resolve === localSchema ? null : localSchema(bare));
    return target ? schemaShape(target, resolve, depth + 1) : null;
  }
  if (!ts.isCallExpression(bare)) return null;
  const callee = unwrap(bare.expression);
  const method = ts.isPropertyAccessExpression(callee) ? callee.name.text : ts.isIdentifier(callee) ? callee.text : "";

  // A chained modifier: `<inner>.optional()`, `<inner>.uuid()`.
  if (ts.isPropertyAccessExpression(callee)) {
    const receiver = unwrap(callee.expression);
    const isChain = ts.isCallExpression(receiver) || (ts.isIdentifier(receiver) && !isLibraryName(receiver));
    if (isChain) {
      const inner = schemaShape(receiver, resolve, depth + 1);
      if (!inner) return null;
      if (OPENING_REFINEMENTS.has(method)) return OPEN;
      if (inner.kind === "open" && (CONSTRAINING_REFINEMENTS.has(method) || ((method === "regex" || method === "matches" || method === "pattern") && safePattern(bare.arguments[0])))) {
        return { kind: "constrained", numeric: method === "integer" || method === "int" || method === "port" };
      }
      if (method === "extend" && inner.kind === "object") {
        const extra = objectFields(bare.arguments[0], resolve, depth);
        return extra ? { kind: "object", fields: new Map([...inner.fields, ...extra]) } : inner;
      }
      if ((method === "pick" || method === "omit" || method === "partial" || method === "required" || method === "deepPartial") && inner.kind === "object") {
        return inner;
      }
      if (method === "array" && inner) return { kind: "array", element: inner };
      if (method === "or" || method === "and") return OPEN;
      if (NEUTRAL.has(method) || CONSTRAINING_REFINEMENTS.has(method)) return inner;
      if (method === "regex" || method === "matches" || method === "pattern") return inner;
      return null;
    }
  }

  // A root builder: `z.string()`, `Joi.object({...})`, `v.pipe(v.string(), v.uuid())` —
  // reached through a library namespace, or a builder imported from one.
  if (!libraryRooted(callee)) return null;
  if (method === "object" || method === "strictObject" || method === "looseObject" || method === "shape") {
    const fields = objectFields(bare.arguments[0], resolve, depth);
    return fields ? { kind: "object", fields } : OPEN;
  }
  if (method === "array") {
    const element = bare.arguments[0] ? schemaShape(bare.arguments[0], resolve, depth + 1) : null;
    return { kind: "array", element: element ?? OPEN };
  }
  if (method === "pipe") {
    // valibot: v.pipe(v.string(), v.uuid()) — the base, refined by every action after it.
    const [base, ...actions] = bare.arguments;
    const shape = base ? schemaShape(base, resolve, depth + 1) : null;
    if (!shape) return null;
    if (shape.kind !== "open") return shape;
    for (const action of actions) {
      const actionBare = unwrap(action);
      if (!ts.isCallExpression(actionBare)) continue;
      const actionCallee = unwrap(actionBare.expression);
      const name = ts.isPropertyAccessExpression(actionCallee) ? actionCallee.name.text : ts.isIdentifier(actionCallee) ? actionCallee.text : "";
      if (CONSTRAINING_REFINEMENTS.has(name)) return { kind: "constrained", numeric: false };
      if ((name === "regex" || name === "pattern") && safePattern(actionBare.arguments[0])) return { kind: "constrained", numeric: false };
      if (OPENING_REFINEMENTS.has(name)) return OPEN;
    }
    return shape;
  }
  if (method === "union" || method === "alternatives") {
    const options = bare.arguments[0] && ts.isArrayLiteralExpression(unwrap(bare.arguments[0]))
      ? (unwrap(bare.arguments[0]) as ts.ArrayLiteralExpression).elements
      : bare.arguments;
    const shapes = options.map((option) => schemaShape(option, resolve, depth + 1));
    if (shapes.length > 0 && shapes.every((shape) => shape?.kind === "constrained")) return { kind: "constrained", numeric: false };
    return OPEN;
  }
  if (method === "coerce") return null;
  if (CONSTRAINED_ROOTS.has(method)) return { kind: "constrained", numeric: CONSTRAINED_ROOTS.get(method)! };
  if (/^(string|email|url|any|unknown|record|map|custom|lazy|mixed|text|binary|object|instanceof)$/.test(method)) return OPEN;
  // `z.coerce.number()`: the receiver is a property access, not a call.
  if (ts.isPropertyAccessExpression(callee) && ts.isPropertyAccessExpression(unwrap(callee.expression))) {
    if (CONSTRAINED_ROOTS.has(method)) return { kind: "constrained", numeric: CONSTRAINED_ROOTS.get(method)! };
    if (method === "string") return OPEN;
  }
  return null;
}

/** `z.string`, `z.coerce.number`, `Joi.object`, or a bare `string` imported from valibot. */
function libraryRooted(callee: ts.Node): boolean {
  let current = callee;
  for (let depth = 0; depth < 4; depth += 1) {
    if (ts.isIdentifier(current)) return isLibraryName(current);
    if (!ts.isPropertyAccessExpression(current)) return false;
    current = unwrap(current.expression);
  }
  return false;
}

function objectFields(node: ts.Node | undefined, resolve: SchemaResolver, depth: number): Map<string, SchemaShape> | null {
  if (!node) return null;
  const bare = unwrap(node);
  if (!ts.isObjectLiteralExpression(bare)) return null;
  const fields = new Map<string, SchemaShape>();
  for (const property of bare.properties) {
    if (!ts.isPropertyAssignment(property)) continue;
    const key = ts.isIdentifier(property.name) || ts.isStringLiteral(property.name) ? property.name.text : null;
    if (!key) continue;
    fields.set(key, schemaShape(property.initializer, resolve, depth + 1) ?? OPEN);
  }
  return fields;
}

/**
 * A call that parses a value against a schema, and what it hands back.
 *
 *  - `S.parse(x)`, `S.parseAsync(x)`, `S.validateSync(x)`, `await S.validate(x)` (yup) → the
 *    parsed value. Not yup's `cast`, which coerces without checking a single refinement;
 *  - `S.safeParse(x)` (zod) → `{ success, data }`; `S.validate(x)` (joi) → `{ value, error }`;
 *  - `v.parse(S, x)`, `v.safeParse(S, x)` (valibot) → the value / `{ success, output }`;
 *  - `Joi.attempt(x, S)` → the value.
 */
export interface SchemaParse {
  shape: SchemaShape;
  /** The value being validated. */
  input: ts.Expression;
  /** Where the validated value sits in the result: `""` for the result itself. */
  path: "" | "data" | "value" | "output";
}

const PARSE_CACHE = new WeakMap<SchemaResolver, WeakMap<ts.Node, SchemaParse | null>>();

export function schemaParse(call: ts.Node, resolve: SchemaResolver = localSchema): SchemaParse | null {
  const bare = unwrap(call);
  if (!ts.isCallExpression(bare) || !ts.isPropertyAccessExpression(unwrap(bare.expression))) return null;
  let cache = PARSE_CACHE.get(resolve);
  if (!cache) {
    cache = new WeakMap();
    PARSE_CACHE.set(resolve, cache);
  }
  if (cache.has(bare)) return cache.get(bare)!;
  const parsed = readParse(bare, resolve);
  cache.set(bare, parsed);
  return parsed;
}

/**
 * `await S.isValid(x)` (yup): a boolean, so it hands nothing back — but as the condition of a
 * guard it says what `x` was checked against, exactly as `S.safeParse(x).success` does.
 */
export function schemaCheck(call: ts.Node, resolve: SchemaResolver = localSchema): { shape: SchemaShape; input: ts.Expression } | null {
  const parsed = schemaParse(call, resolve);
  if (parsed) return parsed;
  const bare = unwrap(call);
  if (!ts.isCallExpression(bare)) return null;
  const callee = unwrap(bare.expression);
  if (!ts.isPropertyAccessExpression(callee) || !/^(isValid|isValidSync)$/.test(callee.name.text)) return null;
  const input = bare.arguments[0];
  const shape = input ? schemaShape(callee.expression, resolve) : null;
  return shape && input ? { shape, input } : null;
}

function readParse(bare: ts.CallExpression, resolve: SchemaResolver): SchemaParse | null {
  const callee = unwrap(bare.expression);
  if (!ts.isPropertyAccessExpression(callee)) return null;
  const method = callee.name.text;
  const receiver = unwrap(callee.expression);
  const receiverName = ts.isIdentifier(receiver) ? receiver.text : "";

  // valibot / joi namespace forms, where the schema is an argument.
  if (/^(v|valibot)$/.test(receiverName) && ts.isIdentifier(receiver) && isLibraryName(receiver) && (method === "parse" || method === "safeParse" || method === "parseAsync" || method === "safeParseAsync")) {
    const [schema, input] = bare.arguments;
    const shape = schema ? schemaShape(schema, resolve) : null;
    if (!shape || !input) return null;
    return { shape, input, path: method.startsWith("safe") ? "output" : "" };
  }
  if (/^(Joi|joi)$/.test(receiverName) && ts.isIdentifier(receiver) && isLibraryName(receiver) && method === "attempt") {
    const [input, schema] = bare.arguments;
    const shape = schema ? schemaShape(schema, resolve) : null;
    if (!shape || !input) return null;
    return { shape, input, path: "" };
  }

  const PARSERS: Record<string, SchemaParse["path"]> = {
    parse: "",
    parseAsync: "",
    validateSync: "",
    safeParse: "data",
    safeParseAsync: "data",
    validate: "",
    validateAsync: ""
  };
  if (!(method in PARSERS)) return null;
  const input = bare.arguments[0];
  if (!input) return null;
  const shape = schemaShape(receiver, resolve);
  if (!shape) return null;
  let path = PARSERS[method]!;
  // Joi's validate returns `{ value, error }`; yup's returns the value (as a promise).
  if (method === "validate" && isJoiSchema(receiver, resolve)) path = "value";
  return { shape, input, path };
}

function isJoiSchema(node: ts.Node, resolve: SchemaResolver, depth = 0): boolean {
  if (depth > 12) return false;
  const bare = unwrap(node);
  if (ts.isIdentifier(bare)) {
    if (/^(Joi|joi)$/.test(bare.text)) return true;
    const target = resolve(bare) ?? localSchema(bare);
    return target ? isJoiSchema(target, resolve, depth + 1) : false;
  }
  if (ts.isCallExpression(bare)) return isJoiSchema(bare.expression, resolve, depth + 1);
  if (ts.isPropertyAccessExpression(bare)) return isJoiSchema(bare.expression, resolve, depth + 1);
  return false;
}

/** The shape at a property path inside a shape. */
export function shapeAt(shape: SchemaShape, path: readonly string[]): SchemaShape | null {
  let current: SchemaShape = shape;
  for (const segment of path) {
    if (current.kind === "object") {
      const next = current.fields.get(segment);
      if (!next) return null;
      current = next;
      continue;
    }
    if (current.kind === "array" && /^\d+$/.test(segment)) {
      current = current.element;
      continue;
    }
    return null;
  }
  return current;
}

/**
 * A resolver that follows imports through the module graph. One per scan, so the parse
 * cache is shared by every file; the file an identifier belongs to is its own source file,
 * which keeps a field schema referenced inside an imported module resolving in *that*
 * module.
 */
export function graphSchemaResolver(graph: ModuleGraph): SchemaResolver {
  const bySource = new Map<ts.SourceFile, ParsedFile>();
  for (const file of graph.files.values()) bySource.set(file.source, file);
  return (identifier) => {
    const local = localSchema(identifier);
    if (local) return local;
    const file = bySource.get(identifier.getSourceFile());
    if (!file) return null;
    const definition = graph.resolveLocal(file, identifier.text);
    return definition && ts.isExpression(definition.node) && !ts.isSourceFile(definition.node) ? definition.node : null;
  };
}

/* ------------------------------------------------------------------- views */

/**
 * What is known about an expression's value from a schema: the shape, sitting under
 * `wrapper` — `["data"]` for a `safeParse` result, `["value"]` for joi's, `[]` once the
 * validated value itself has been reached.
 */
export interface SchemaView {
  shape: SchemaShape;
  wrapper: readonly string[];
}

/** What a function body has established about schemas, consulted by `schemaViewOf`. */
export interface SchemaFacts {
  resolve: SchemaResolver;
  /** Local bindings that hold a parse result or a validated value. */
  views: ReadonlyMap<string, SchemaView>;
  /** Inputs a terminating guard validated in place, by dotted path (`req.body`, `body`). */
  guards: ReadonlyMap<string, SchemaShape>;
}

function dottedText(node: ts.Node): string | null {
  const bare = unwrap(node);
  if (ts.isIdentifier(bare)) return bare.text;
  if (ts.isPropertyAccessExpression(bare)) {
    const base = dottedText(bare.expression);
    return base ? `${base}.${bare.name.text}` : null;
  }
  return null;
}

/** One property step into a view. */
export function stepView(view: SchemaView, key: string): SchemaView | null {
  if (view.wrapper.length > 0) return view.wrapper[0] === key ? { shape: view.shape, wrapper: view.wrapper.slice(1) } : null;
  const inner = shapeAt(view.shape, [key]);
  return inner ? { shape: inner, wrapper: [] } : null;
}

/**
 * The schema view of an expression, or null when no schema speaks for it.
 *
 * A field the schema does not declare has no view: zod strips it from a parsed object, but
 * a guard leaves it on the original, and either way this reader does not claim to know it.
 */
export function schemaViewOf(node: ts.Node, facts: SchemaFacts, depth = 0): SchemaView | null {
  if (depth > 8) return null;
  const bare = unwrap(node);
  if (facts.guards.size > 0) {
    const path = dottedText(bare);
    const guarded = path ? facts.guards.get(path) : undefined;
    if (guarded) return { shape: guarded, wrapper: [] };
  }
  if (ts.isIdentifier(bare)) return facts.views.get(bare.text) ?? null;
  if (ts.isPropertyAccessExpression(bare)) {
    const base = schemaViewOf(bare.expression, facts, depth + 1);
    return base ? stepView(base, bare.name.text) : null;
  }
  if (ts.isElementAccessExpression(bare)) {
    const argument = unwrap(bare.argumentExpression);
    if (!ts.isStringLiteralLike(argument) && !ts.isNumericLiteral(argument)) return null;
    const base = schemaViewOf(bare.expression, facts, depth + 1);
    return base ? stepView(base, argument.text) : null;
  }
  if (ts.isCallExpression(bare)) {
    const parsed = schemaParse(bare, facts.resolve);
    return parsed ? { shape: parsed.shape, wrapper: parsed.path ? [parsed.path] : [] } : null;
  }
  return null;
}

/** The view is the validated value itself, and the schema constrains all of it. */
export function constrainedValue(view: SchemaView | null): { numeric: boolean } | null {
  if (!view || view.wrapper.length > 0 || view.shape.kind !== "constrained") return null;
  return { numeric: view.shape.numeric };
}

/** The resolver a file should use: the scan's graph-backed one when installed. */
export function defaultSchemaResolver(): SchemaResolver {
  return localSchema;
}
