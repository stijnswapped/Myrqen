# Detection baseline

<!-- historical: 2026-08-19 -->

> **Superseded 2026-08-24. Every figure in this document is history.** It was
> written before `benchmark/holdout-3` existed and stops at holdout-2, so the
> number it calls "the honest number" is **0.091** — a ratio out of eleven cases,
> on a corpus that has since been burned. The current figures are **0.294** blind
> and **0.500** after the fixes that run prompted, both the static pass alone.
>
> Nothing below has been edited: a baseline that gets rewritten every time the
> baseline moves is not a baseline. For current numbers use
> [`docs/internal/detection-baseline.md`](../internal/detection-baseline.md), and
> for the full run history `HOLDOUT-PROTOCOL.md`.

Captured before any scanner change in this work stream, on the tree at
`1aed39a` plus the uncommitted README/packaging edits. Every number here comes
from a recorded command; nothing is estimated.

Reproduce with:

```bash
pnpm build
node benchmark/run.mjs                                   # fixture end-to-end
node benchmark/score-corpus.mjs                          # development corpus
node benchmark/score-corpus.mjs --corpus benchmark/holdout   # held-out corpus
```

## What each benchmark measures

| Benchmark | Subject | Ground truth |
|---|---|---|
| `benchmark/run.mjs` | The whole session pipeline — static pass, agent protocol, validation, dedupe, policy gates, report writing — against two local fixtures | `fixtures/*/ground-truth.json` |
| `benchmark/score-corpus.mjs` | The static engine alone (`packages/scan`), one case per scan in an isolated temp directory | `benchmark/corpus/manifest.json` |
| `--corpus benchmark/holdout` | The same static engine against architectures it was never tuned on | `benchmark/holdout/manifest.json` |

## Static engine — development corpus

156 cases: 73 vulnerable, 73 safe, 10 in a language the engine does not parse.

| Metric | Value |
|---|---|
| Overall recall | 1.000 (73/73) |
| Critical/high recall | 1.000 (69/69) |
| Precision | 1.000 |
| Safe-case false-positive rate | 0.000 (0/73) |

Not assessed: 10 Python cases (the engine parses only JavaScript/TypeScript).

## Static engine — held-out corpus

60 cases: 27 vulnerable, 27 safe, 6 in an unparsed language (Ruby, PHP, Go).

| Metric | Value |
|---|---|
| Overall recall | **0.148** (4/27) |
| Critical/high recall | **0.160** (4/25) |
| Precision | **0.571** |
| Safe-case false-positive rate | **0.111** (3/27) |

Gate result: **4 of 4 gates failed.**

### The gap is the honest number

A perfect development corpus next to a 0.148 held-out corpus is not a scanner
that works with a few gaps. It is a scanner that has learned the nine
architectures in `benchmark/corpus` and generalises to almost nothing else. The
release gates are written against the development corpus, so they currently pass
while the product would fail on a real unfamiliar repository.

### Held-out classes with zero detections

`argument_injection`, `template_injection`, `path_traversal`,
`insecure_randomness`, `sql_injection`, `jwt_verification_bypass`,
`prototype_pollution`, `business_logic_price_manipulation`,
`broken_object_level_authorization`, `command_injection`,
`broken_function_level_authorization`, `mass_assignment`, `nosql_injection`,
`verbose_error_response`, `insecure_cookie_configuration`,
`server_side_request_forgery`, `reflected_cross_site_scripting`,
`missing_authentication`, `insecure_cors_configuration`, `open_redirect`,
`unsafe_deserialization`, `sensitive_data_in_logs`.

### False positives on correct code

| Case | Rule | Line |
|---|---|---|
| `holdout-nestjs-ledger-conversion` | `perimeter-path-traversal` | 62 |
| `holdout-sveltekit-report-stream` | `perimeter-path-traversal` | 26 |
| `holdout-sveltekit-embed-preview` | `perimeter-ssrf` | 23 |

### Root cause, measured per case

Running each held-out vulnerable case through the engine and printing both the
route coverage and the raw candidates separates two different failures:

1. **No entry point is recognised, so no taint source exists.** The engine
   discovers HTTP routes from `app.get("/x", handler)`, from hand-rolled
   `METHOD /path` dispatch, from a regex tested against a pathname, from
   GraphQL resolver maps, from tRPC routers, and from Next.js `app/**/route.ts`.
   It recognises none of: NestJS controller decorators, SvelteKit `+server.ts`
   and `+page.server.ts`, Nitro/Nuxt `server/api/**/*.get.ts` with
   `defineEventHandler`, AWS Lambda `exports.handler(event)`, Cloudflare Worker
   `export default { fetch(request, env) }`, Electron `ipcMain.handle`, BullMQ
   `new Worker(queue, async (job) => …)`, or a `commander` `.action()` callback.
   With no entry point, `event.queryStringParameters`, `job.data`, `getQuery(event)`
   and an IPC argument are all treated as ordinary local values, and every
   taint-driven rule stays silent.

2. **The defect is found but attributed to the wrong route.** Four cases produce
   a candidate at exactly the ground-truth line and still score as a miss,
   because the file-path route deriver understands only Next.js `app/` and
   `pages/`. A SvelteKit `routes/api/exports/[name]/+server.ts` reports no route
   at all, so `satisfies()` rejects a correct detection.

Both are architecture coverage, not rule quality: the same rule that finds a
path traversal in an Express handler finds nothing in a SvelteKit endpoint
because it never learns which value the caller controls.

## End-to-end fixture benchmark

| Fixture | Recall | Precision | Findings | Verified | FP | Duplicates | Canary leaks | Unsafe blocked | Duration |
|---|---|---|---|---|---|---|---|---|---|
| `vuln-shop` | 1.00 (critical/high 1.00) | 1.00 | 14 | 9 | 0 | 0 | 0 | 4 blocked, 0 allowed | 16.2s |
| `safe-app` | n/a | n/a | 0 | 0 | 0 | 0 | 0 | 4 blocked, 0 allowed | 9.8s |

Effort `auto` resolved to `high` in both runs. All gates passed with no
regression against `benchmark/baseline.json`.

## Token accounting

Token usage is **unavailable** in these runs. The fixture benchmark drives a
scripted agent rather than a model, and the static engine spends no tokens. The
session protocol accepts `myrqen metrics token --source exact|estimated|unavailable`,
so a real host agent can report it, but nothing in the benchmark harness does.
Any token figure in this document would be invented, so none is given.

## Effort modes

`low`, `auto`, `high`, `xhigh`, `ultra` are accepted by the CLI and resolved by
`packages/policy/src/effort.ts`. The benchmark exercises `auto` only. Per-mode
recall/precision/duration is therefore **not measured** at baseline.

---

# After

Measured on the same commands, on a clean build, at the end of this work stream.

## Static engine — the three corpora

| | Development corpus | Held-out 1 | Held-out 2 (blind) |
|---|---|---|---|
| Cases | 156 (73 vuln / 73 safe) | 60 (27 / 27 scored) | 76 (11 / 11 scored) |
| Overall recall | 1.000 → **1.000** | 0.148 → **1.000** | — → **0.091** |
| Critical/high recall | 1.000 → **1.000** | 0.160 → **1.000** | — → **0.091** |
| Precision | 1.000 → **1.000** | 0.571 → **1.000** | — → **0.500** |
| Safe-case FP rate | 0.000 → **0.000** | 0.111 → **0.000** | — → **0.091** |

Read those three columns together, because separately each one misleads.

**The development corpus proves nothing.** It was 1.000 before this work and it
is 1.000 after. A corpus a rule was written against cannot tell you whether the
rule generalises.

**Held-out 1 went from 0.148 to 1.000, and is now burned.** That movement is
real and the mechanism behind it is the point: an entry-point adapter layer
(`packages/scan/src/ast/entrypoints.ts`, `packages/scan/src/ast/frameworks/`)
that teaches the engine where caller-controlled data enters an application, per
architecture. Nine architectures gained one. But the corpus was scored, then the
engine was changed in response to what it said, so by this repository's own rule
the 1.000 is a development number wearing a holdout's clothes. It is quoted here
only next to the column that matters.

**Held-out 2 is the honest number, and it is 0.091.** Authored blind by five
independent authors after held-out 1 was burned, deliberately avoiding every
architecture that now has an adapter — Deno, Bun, Astro, TanStack Start,
Socket.IO, Server-Sent Events, a browser-extension service worker. Ten of its
eleven scored cases produced **no candidate at all**: no entry point recognised,
so no value is caller-controlled, so no data-flow rule can fire.

The conclusion is structural, and it is the most useful thing this measurement
produced:

> The adapter layer works. Its coverage is per-architecture. An application built
> on a framework with no adapter is very nearly invisible to this engine.

Caveat worth stating plainly: 54 of held-out 2's 76 cases are Python, Java, Ruby
or Go, which the engine does not parse and which the scorer excludes rather than
counting as misses. The scored population is 11 vulnerable and 11 safe. A ratio
out of eleven is a weak estimate and should not be quoted without that sentence
attached.

## What changed in the engine

| Area | Change |
|---|---|
| Entry points | New adapter layer. NestJS and decorator frameworks, SvelteKit, Remix, Nitro/Nuxt/h3, AWS Lambda and API Gateway, Cloudflare Workers and edge runtimes, Azure and GCP functions, Electron IPC, BullMQ/Kafka/SQS/AMQP consumers, `node:worker_threads`, and commander/yargs CLIs. Each declares both the address *and* which bindings hold caller data. |
| Taint | Server-attached properties are now judged one level deep, not along the whole path — a request field named `state`, `account`, `auth`, `tenant`, `identity` or `subject` no longer silently disarms taint. Bindings and collections are analysed in alternating rounds, so `const sql = clauses.join(…)` written above the pushes that taint it is followed. Array literals drained by `.join()` carry taint. Module-level string constants are resolved, so a query assembled from a constant prologue is still recognised as SQL. |
| Rules | Decorator-declared authorization, whole-object mass assignment, webhook signature verification as authentication, credential-carrying values in logs, TypeORM ownership scoping, remote template compilation, argument injection with no shell, JWT verify matching scoped to the decode's own function, and `process.stderr.write` no longer counted as a caller-facing response. |
| Honesty | A scan that recognises no entry point in a file now says so in its coverage, and says that a clean result is unproven when most of the project was not understood. |

## End-to-end fixture benchmark

| Fixture | Recall | Precision | FP | Canary leaks | Unsafe blocked | Duration |
|---|---|---|---|---|---|---|
| `vuln-shop` | 1.00 (critical/high 1.00) | 1.00 | 0 | 0 | 4 blocked, 0 allowed | 16.8s |
| `safe-app` | n/a | n/a | 0 | 0 | 4 blocked, 0 allowed | 9.4s |

All gates pass with no regression against `benchmark/baseline.json`.

A false positive appeared here during the work and was fixed: a `catch` block
that logged `error.message` to stderr and returned a fixed string to the caller
was reported as a verbose error response, because `write` was on the
response-writer list and `process.stderr.write` matched it.

## Test suites

| Suite | Result |
|---|---|
| `packages/scan` | 398/398 |
| `packages/report` | 56/56 |
| `apps/cli` | 126/126 |
| `tests/deploy.test.mjs` | 18/18 |

## Token accounting

Still **unavailable**, for the same reason as at baseline: the harness drives a
scripted agent rather than a model, and the static engine spends no tokens. The
session protocol accepts `myrqen metrics token --source exact|estimated|unavailable`,
so a real host agent can report it. No token figure is given here because any
figure would be invented.

## Effort modes

`low`, `auto`, `high`, `xhigh` and `ultra` resolve correctly through
`packages/policy/src/effort.ts`, and the fixture benchmark exercises `auto`
(which resolves to `high` on both fixtures). Per-mode recall and precision are
**still not measured**: effort is a policy profile applied to the host agent's
reasoning, and the benchmark's scripted agent does not vary with it. Measuring it
honestly needs a model-driven harness that does not exist yet.
