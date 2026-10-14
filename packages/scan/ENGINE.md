# The scan engine, for rule authors

This is the API a rule in `src/rules/` builds on. It covers what the engine knows about a
project before any rule runs, and how a rule asks. The design and its bounds are recorded in
[ADR 018](../../docs/adr/018-cross-file-taint.md); this file is the reference.

A rule still sees **one file at a time** (`Rule.run(context)` is called per parsed file).
Everything cross-file arrives through the `ParsedFile` and `RuleContext` it is handed, which
`scan()` fills in before the first rule runs. A rule never builds a module graph itself.

## The order `scan()` works in

1. Discover and parse every source file (`ast/parse.ts`).
2. Build the one-hop call-site index (`ast/call-sites.ts`) → `ParsedFile.observedParameters`.
3. Build the module graph (`engine/modules.ts`) and install, on every file:
   `resolveSchema`, `returnSummary`.
4. Find request handlers by position (`engine/handlers.ts`) and parameters bound by framework
   request decorators (`engine/decorators.ts`) → `ParsedFile.requestSeeds`,
   `ParsedFile.requestHandlerOf`.
5. Propagate caller data across calls and modules (`engine/interproc.ts`) →
   `ParsedFile.parameterSeeds`, `ParsedFile.propertySeeds`; route inheritance →
   `ParsedFile.seedRouteOf`.
6. Run the rules.

All of it is deterministic (ADR 012): files are processed in sorted order, every bound is a
fixed constant, and nothing depends on timing or randomness.

## The taint model — `src/ast/taint.ts`

The entry point for every data-flow rule.

```ts
analyzeFunction(file: ParsedFile, fn: ts.Node, options?: AnalyzeOptions): TaintScope
taintOrigin(node: ts.Node, scope: TaintScope): string | null      // can this carry caller *text*?
valueTaintOrigin(node: ts.Node, scope: TaintScope): string | null // is this the caller's *value*?
isSchemaConstrained(node: ts.Node, scope: TaintScope): boolean
isSanitizingCall(call: ts.CallExpression, scope: TaintScope): boolean
functionsIn(source: ts.SourceFile): ts.Node[]
```

`taintOrigin` answers the injection question: `Number(x)` and a `z.string().uuid()` field are
clean. `valueTaintOrigin` answers the business-logic question: `Number(req.body.qty)` and a
`z.number()` field are still the caller's amount. Use the one that matches the defect.

`analyzeFunction` seeds a scope from, in order of precedence (a later source never overwrites
a binding an earlier one set, and an adapter's `trustedParameters` always wins):

| source | where it comes from |
|---|---|
| request parameters by name or type (`req`, `request`, `ctx`, `: Request`) | the function itself |
| `entry.seeds` | a framework adapter in `ast/frameworks/` |
| `file.observedParameters` | the one-hop call-site index |
| `file.requestSeeds` | handler position (`engine/handlers.ts`) and request decorators (`engine/decorators.ts`) |
| `file.parameterSeeds`, `file.propertySeeds` | inter-procedural propagation |

`AnalyzeOptions.isolate` with `seeds` analyses a function with only the given parameters
seeded — what the function summariser uses.

### `TaintScope`

| field | meaning |
|---|---|
| `roots` | bindings holding caller data, with a human-readable origin used verbatim in evidence |
| `cleared` | bindings a guard or sanitiser made safe; checked before `roots` |
| `coerced` | cleared only by numeric coercion — still the caller's value |
| `allowlisted`, `containmentChecked` | cleared by an allowlist, or resolved and checked against a base directory |
| `clearedPaths` | dotted paths cleared by an equality guard (`request.method === "GET"`) |
| `taintedPaths` | dotted paths that hold caller data although their root does not (`options.term`) |
| `validated` | bindings a terminating guard *tested*, strong enough or not — see "observed" below |
| `schemaFacts` | schema views and guards for this function — see "schemas" below |
| `initializers` | what each local was initialised from, for rules that need the expression's shape |
| `file` | the `ParsedFile`, so the model can consult project-level summaries |

## Observed, not inferred — `src/engine/observed.ts`

```ts
observedOrigin(node, scope): string | null
observedCallerValue(node, scope): boolean
```

Inside a function the model assumes an unknown function handed caller data returns caller
data. Across a call boundary that assumption invents flows, so anything that **crosses a
boundary** must be *observed*: every step back to the origin is one the engine reads — a
request read, a property, a local, a transparent string operation, a schema parse, or a
project function whose body was read and found to return the argument. A binding in
`scope.validated` is not observed. Use `observedOrigin` whenever a rule hands a value to
something outside the function it was found in.

## The module graph — `src/engine/modules.ts`

```ts
buildModuleGraph(repoRoot: string, files: readonly ParsedFile[]): Promise<ModuleGraph>

interface ModuleGraph {
  files: ReadonlyMap<string, ParsedFile>;               // by repository-relative path
  resolveSpecifier(from, specifier): string | null;      // relative, tsconfig/jsconfig paths+baseUrl+extends, index files
  resolveLocal(file, localName): Definition | null;      // imported or locally declared
  resolveMember(file, receiver, member): Definition | null;
  exportOf(file, exportName): Definition | null;         // follows re-exports and `export *`
  localDefinition(file, name): Definition | null;
  memberOf(definition, member): Definition | null;       // object property, class method (one `extends`), instance method
  importOf(file, localName): { target: ParsedFile | null; imported: string } | null;
}
interface Definition { file: ParsedFile; node: ts.Node }
```

`Definition.node` is a function-like node, a class, an object literal, a `new` expression (a
singleton), a source file (a namespace or a CommonJS `require` of a whole module), or — for
`export const X = …` — the initialiser expression. ESM, CommonJS (`require`,
`module.exports`, `exports.x`), default and namespace imports, re-exports and path aliases
are all resolved; resolution is lazy and memoised per file.

## Call resolution — `src/engine/callgraph.ts`

```ts
resolveCall(graph, file, call: ts.CallExpression | ts.NewExpression): CallTarget | null
interface CallTarget { file: ParsedFile; fn: ts.FunctionLikeDeclaration }
isCallableBody(node): node is ts.FunctionLikeDeclaration
```

Resolves lexical-scope functions, imports, `this.method()`, `this.member.method()` through
typed constructor parameters, typed properties and constructor assignments, locals holding
`new C()`, and constructors. A call it cannot resolve returns `null`; never guess a target.

## Function summaries — `src/engine/summaries.ts`

```ts
createReturnSummariser(graph): (file, call, argumentIndex) => ReturnSummary | null
interface ReturnSummary { tainted: boolean; observed: boolean }
```

Installed as `ParsedFile.returnSummary`. `tainted: false` means no return of the resolved
project function carries that argument, so `taintOrigin` clears the call's result (a
validating helper, a parser returning a number, a schema parse of a constrained value).
`observed` means a return hands the argument back by steps the engine reads. A library call,
an unresolved call, a recursive call and a function reading `arguments` get `null`: the
default stands.

## Propagation — `src/engine/interproc.ts`

```ts
propagateTaint(graph, files, { handlers }): InterproceduralResult
INTERPROCEDURAL_LIMITS // maxHops 4, maxCallerFiles 2, maxCallerFunctions 4, maxVisitsPerFunction 6, maxRestarts 3, maxClosureDepth 4
```

A fixed point over resolved call edges. A chain starts only in a function that receives
caller data by contract (`isRequestHandler`) and carries only observed taint. A parameter
filled with caller data from more than `maxCallerFiles` other files or `maxCallerFunctions`
callers is a utility (a logger, a file helper) and is not seeded. Command-line input is not
propagated. Results land on the files as `parameterSeeds` / `propertySeeds`, which
`analyzeFunction` reads — a rule needs no code to benefit. `RuleContext.taintedParameters`
is the name-keyed view (`exported name → index → origin`) for rules that look parameters up by
name, such as the record-ownership rule.

`ParsedFile.seedRouteOf(fn)` gives a seeded helper the route of the handler that reached it,
when all its seeding call sites agree; route attribution uses it automatically.

## Request handlers and middleware — `src/engine/handlers.ts`

```ts
requestHandlers(graph, file): RequestHandler[]          // registrations written in `file`
handlerPositions(graph, files): Map<ts.Node, RequestHandler>
isRequestHandler(file, fn, handlers): boolean
registrationGate(file, chain: readonly ts.Node[]): RegistrationGate | null

interface RequestHandler {
  file: ParsedFile;          // where the handler function is declared
  registeredIn: ParsedFile;  // where the registration is written
  fn: ts.FunctionLikeDeclaration;
  framework: string;
  method: string;            // HTTP verb, or "ANY"
  path: string | null;
  line: number;
  requestParameters: number[];
  middleware: MiddlewareRef[];   // in order, router-level `use` first
  isMiddleware: boolean;
}
interface MiddlewareRef { expression; name; fn; file; authenticates: boolean; authorizes: boolean }
interface RegistrationGate { authenticates: boolean; authorizes: boolean; names: string[] }
```

Recognises Express/Router/Koa-router/Hono/Fastify shorthand and `route()` registrations,
Fastify `route({ … })`, `x.use(fn)` ahead of routes, `http(s).createServer`, Next.js App
Router route handlers (including wrapped exports) and pages API routes. Handlers may be
inline, local, imported, members (`controller.show`) or wrapped (`asyncHandler(fn)`).

`ParsedFile.requestHandlerOf(fn)` returns a function's registration from anywhere in the
project. Prefer `registrationGate(context.file, chain)` in a rule: it unions the middleware
of every registered function in the enclosing chain and returns `null` when none is
registered, so "no gate" and "not known" stay distinct. Middleware mounted on a router in a
*third* module (`app.use("/api", requireAuth, router)`) is not visible; do not treat the
absence of authentication in a gate as proof that a route is public.

## Request decorators — `src/engine/decorators.ts`

```ts
decoratedParameterSeeds(file): Map<ts.Node, Map<number, string>>
```

Parameters bound by a framework's request decorator in any method — NestJS
(`@Param @Query @Body @Headers @Req @Ip …`), `@nestjs/graphql` `@Args`, `@nestjs/websockets`
`@MessageBody`, type-graphql `@Arg`, routing-controllers, Ts.ED, tsoa and
inversify-express-utils. A decorator counts only when imported from the framework that
defines it. Installed into `requestSeeds`, so such a method also starts a propagation chain.

## Schemas — `src/engine/validation.ts`

```ts
schemaShape(node, resolve?): SchemaShape | null
schemaParse(call, resolve?): SchemaParse | null      // { shape, input, path: "" | "data" | "value" | "output" }
schemaCheck(call, resolve?)                           // schemaParse, or yup's isValid/isValidSync
schemaViewOf(node, facts): SchemaView | null          // { shape, wrapper }
constrainedValue(view): { numeric: boolean } | null
graphSchemaResolver(graph): SchemaResolver            // installed as ParsedFile.resolveSchema

type SchemaShape =
  | { kind: "constrained"; numeric: boolean }   // number, boolean, enum, literal, uuid/cuid/ulid, ISO date, anchored safe regex …
  | { kind: "open" }                             // string, email, url, any, record, transform …
  | { kind: "object"; fields: Map<string, SchemaShape> }
  | { kind: "array"; element: SchemaShape };
```

zod, yup, joi and valibot, including imported schemas and field schemas declared beside the
object. A schema is read only when it bottoms out in a validation library's namespace or an
imported builder; anything else returns `null` and the taint model behaves as before.
`analyzeFunction` applies it for you: parse results are read field by field, and a terminating
guard (`if (!S.safeParse(req.body).success) return`, `const r = S.safeParse(…); if
(!r.success) …`, joi `{ error }`, yup `isValid`, or a throwing `S.parse(x)` statement outside
a swallowing `try`) validates its input in place. yup's `cast` is not validation. Rules
normally only need `isSchemaConstrained` or nothing at all.

## Writing a rule against this

- Ask `taintOrigin` / `valueTaintOrigin` of the value at the sink; do not re-derive taint.
- Use `observedOrigin` for anything that leaves the function.
- A finding inside a helper reached from a handler gets its route through
  `seedRouteOf` automatically; use `routeHintFor`/`locationOf` from `rules/context.ts`.
- Use `registrationGate` for "is this route authenticated / authorised by middleware"; keep
  the same-file reading you already do, the gate only adds what another module declared.
- Every positive test needs a near-miss negative beside it (see `test/engine-*.test.mjs`).
- Measure on `benchmark/corpus` and `--corpus benchmark/reference --split dev` only; the
  held-out corpora are scored once and recorded in `docs/12-release/HOLDOUT-PROTOCOL.md`.
