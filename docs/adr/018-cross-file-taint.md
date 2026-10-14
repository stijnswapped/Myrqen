# ADR 018: The static pass follows caller data across functions and modules, where a call resolves

Status: Accepted (0.3.0).

## Context

Until 0.3.0 the taint model in `packages/scan` was intra-procedural. A value was caller data
only inside the function that read it from the request, so every application written in
layers — a route in one module, a controller in a second, a service with the query in a
third — had its sink in a function where nothing was caller-controlled, and every data-flow
rule was correct and silent there. The product said so plainly ("data flow is followed within
a single function") and handed the rest to the host agent.

Three further gaps had the same shape, a fact the engine could not see from inside one
function:

- **Schema validation was modelled wrong in both directions.** `Body.parse(req.body)` was an
  unknown function handed caller data, so a `z.string().uuid()` field interpolated into SQL
  was injection; and `if (!Body.safeParse(req.body).success) return` cleared the *whole
  request*, so a `z.string()` field — which constrains nothing about its content — read as
  safe.
- **Decorator-bound parameters outside a routed controller method** — a GraphQL resolver's
  `@Args('id')`, a WebSocket gateway's `@MessageBody()`, a tsoa `@Path()` — were ordinary
  parameters.
- **Middleware registered in another module** was invisible to the object- and
  function-level authorization rules, which read a handler one file at a time.

The constraint is the one this engine was built on: a scanner that over-reaches produces the
false positives it exists to avoid. An earlier widening of taint across a boundary reported
this repository's own validated executable path, and was closed by requiring *observed*
rather than *inferred* taint across a call.

## Decision

The engine computes, once per scan and before any rule runs, what crosses function and module
boundaries, and hands it to the existing per-file taint model as seeds. Rules keep seeing one
file at a time. The API is documented for rule authors in `packages/scan/ENGINE.md`.

1. **Module graph** (`engine/modules.ts`): ESM and CommonJS imports and exports, default and
   namespace imports, re-exports and `export *`, `tsconfig`/`jsconfig` `paths`, `baseUrl` and
   `extends`, index files, object and singleton modules. Lazy and memoised.
2. **Call resolution** (`engine/callgraph.ts`): lexical scope, imports, `this.m()`,
   `this.member.m()` through typed constructor parameters and properties, locals holding
   `new C()`, one level of `extends`, constructors. An unresolved call has no target; it is
   never guessed.
3. **Handlers by position** (`engine/handlers.ts`): the function a router or server is handed
   receives the request in a fixed position whatever it is named, wherever it is declared —
   Express, Router, Koa-router, Hono, Fastify, `createServer`, Next.js route handlers and pages
   API routes — together with the middleware in front of it, classified as authenticating or
   authorising.
4. **Request decorators** (`engine/decorators.ts`): a parameter bound by a framework's request
   decorator is caller data in any method, when the decorator is imported from the framework
   that defines it.
5. **Propagation** (`engine/interproc.ts`): a fixed point over resolved call edges, starting
   only in a function that receives caller data by contract, carrying only *observed* taint
   (`engine/observed.ts`), per parameter and per field of an object argument, at most **four
   calls** deep. A parameter filled from more than **two** other modules or **four** callers
   is a shared utility and is not seeded. Command-line input is not propagated.
6. **Summaries** (`engine/summaries.ts`): a call into a project function whose returns provably
   do not carry an argument clears the result; anything unreadable keeps the default.
7. **Schemas** (`engine/validation.ts`): zod, yup, joi and valibot schemas, including ones
   imported from another module, are read field by field. A constrained field (number,
   boolean, enum, literal, UUID-like, ISO date, anchored safe pattern) is not caller *text*;
   a number stays the caller's *value* for the monetary rules; an open field stays tainted,
   including after a guard validated the object. A schema the engine cannot read leaves the
   earlier behaviour unchanged. yup's `cast` is not validation.
8. **Middleware in the authorization rules**: the record-ownership (BOLA) rule counts
   authenticating middleware in a cross-module registration as an established identity and an
   object-level guard's name as the guard, exactly as it already did for a same-file
   registration; the function-level (BFLA) rule judges handlers registered in another module
   and treats authorising middleware as the role check. The missing-authentication rule does
   not use it (see Consequences).

**Determinism (ADR 012).** Files are processed in sorted order, every bound is a fixed
constant (`INTERPROCEDURAL_LIMITS`), caches are keyed by syntax node, and nothing depends on
time, randomness or iteration order of a hash. Two scans of the same tree produce the same
candidates.

**No held-out tuning.** Development used `benchmark/corpus`, the dev half of
`benchmark/reference`, paired positive / near-miss tests and a self-scan. No adapter was
written for a family that appears only in a held-out corpus. The scoring of held-out corpora
during this work, and the three held-out case files that were read to diagnose an
intermediate regression, are recorded in `docs/12-release/HOLDOUT-PROTOCOL.md`.

## Consequences

- **Measured effect is small, and honest about it.** Against the integration base, no corpus
  lost a true positive or precision; one holdout-2 case is now credited because a helper
  inherits its caller's route; nothing else moved on any corpus. The held-out misses stop at
  a local predicate before a module boundary matters, as the gap analysis predicted. The work
  shows in paired tests and in this repository's self-scan (two false positives gone). It is
  not evidence of better recall on unseen code, and must not be described as such.
- **Precision ≥ 0.95 still does not hold** on holdout-4 to holdout-7 and reference-holdout. It
  did not at the base either; this ADR neither caused nor fixed it.
- **Cost:** about +6% on the performance gate's subjects with the same inputs.
- **Still not connected:** event emitters, queues, stored callbacks, dynamic dispatch
  (`handlers[name](x)`), calls through values the graph cannot resolve, getters and setters,
  more than one level of class inheritance, and middleware mounted on a router in a *third*
  module (`app.use("/api", requireAuth, router)`). The last is why the missing-authentication
  rule does not consume the registration gate: an invisible mount-level gate would make every
  sibling route look unauthenticated alike.
- **Public wording changes** from "within a single function" to "across modules only where a
  call resolves", with the bounds; `docs/internal/product-truth.md` carries the row, marked
  unreleased until 0.3.0 ships. 0.2.0 must not be described as following data across modules.
