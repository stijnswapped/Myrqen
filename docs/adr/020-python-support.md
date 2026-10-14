# ADR 020: Python support (FastAPI and Flask) as a separate static engine

Status: Accepted (0.3.0).

## Context

Until 0.3.0 the static pass parsed only JavaScript and TypeScript. A Python project
produced no candidates at all. The coverage note said "Only JavaScript and TypeScript
source is parsed", but a clean report on a Flask app still read as a clean bill of
health. Of the server-side Python stacks that people point a coding agent at, FastAPI
and Flask are the most common, and their entry points are explicit enough to model
deterministically (ADR 012).

The constraints carry over from the JavaScript engine:

- deterministic;
- local;
- no Python interpreter required at scan time;
- no network;
- findings in the shape the report, SARIF export, dedupe, and compliance mapping
  already understand.

## Decision

**A separate package, `packages/scan-python`.** It discovers `.py` files, parses them,
builds a project model, runs a taint interpreter, and returns candidates. It is called
from exactly one place, `scan()` in `packages/scan/src/index.ts`. That call, and the
merge of its coverage into the existing coverage object, is the whole seam. Everything
downstream (dedupe, intake, report, SARIF, baseline, triage) treats a Python candidate
exactly as it treats a JavaScript one.

**The dependency runs one way.** `@myrqen/scan` depends on `@myrqen/scan-python`, never
the reverse. The candidate type is declared again in `scan-python/src/types.ts` rather
than imported. TypeScript's structural typing makes the two interchangeable, so a field
added on one side and not the other fails to compile at the call site. The credential
shapes used by the hardcoded-secret rule are mirrored from the JavaScript engine for the
same reason. `scan-python/test/credentials.test.mjs` compares the two lists, so drift
fails the build.

**Parser: `@lezer/python` 1.1.19** (with `@lezer/common` 1.5.3 and `@lezer/lr` 1.4.10).
All three are MIT-licensed pure JavaScript. The parser is incremental and
error-tolerant, so a file with a syntax error still yields a tree for the parts that
parse. It adds about 88 KB minified, or 33 KB gzipped. The alternative,
tree-sitter-python through web-tree-sitter, would have added about 760 KB of WASM,
asynchronous initialisation, and a native-artefact path in the npm package for every
platform. Running CPython's own `ast` module would have made a Python interpreter a
runtime requirement of a Node CLI, which it must not be. Lezer has one known grammar
quirk: it binds `not` more loosely than `and`/`or`. The converter corrects for this
(`negate()` in `syntax/expressions.ts`), and a unit test pins it.

**Architecture.**

- `syntax/` converts the concrete tree into a small AST: statements, expressions, and
  spans.
- `project/` resolves modules and imports, including relative ones and package
  `__init__` re-exports. It reads Pydantic models and type annotations, which is how
  `item_id: int` or a `Literal[...]` field becomes clean. It models the two frameworks:
  - FastAPI: `APIRouter` and `include_router` prefixes, `Depends` authentication.
  - Flask: `Blueprint` and `register_blueprint` prefixes, `login_required`,
    `before_request`.
  - Both: mounts written inside loops and application factories.
- `analysis/` is the taint interpreter. Handler parameters are seeded from the
  framework model. Flask's `request` object is a source. Guards (allow-list
  membership, containment checks, `int()`, regex `fullmatch` with a refusal) clean what
  they cover. Function summaries carry taint across modules. A helper that executes
  whatever statement it is handed is decided at its call site against the caller's
  value, and reported there.
- `rules/` has three groups:
  - Flow rules: SQL, command, path, SSRF, server-side template injection,
    deserialisation, open redirect, and reflected XSS.
  - Config rules: hardcoded secrets, debug mode, cookie flags.
  - Access rules: a route missing authentication next to authenticated siblings, and
    object-level authorisation.

Category names are the ones the JavaScript engine already uses wherever the meaning
matches. Rule ids carry a `py-` prefix. The compliance test walks both engines' sources,
so a new Python category without a compliance row fails the build.

**The CLI treats `requirements.txt`, `setup.py` and `Pipfile` as a project root**,
alongside `pyproject.toml`. Before this, a Flask app with only `requirements.txt` made
the CLI walk up to an enclosing directory and scan (and write `.myrqen/`) there.

**Runtime verification is unchanged.** It is still the host agent's part. The skill
tells the agent how to start a FastAPI or Flask app. The harness starts the two Python
fixtures through `python3` and skips them, saying so, when the fixture's packages are
not installed. Myrqen itself never needs Python.

## Limits, stated in every report that parsed Python

- Django, Flask `MethodView` and other class-based views, plain Starlette, aiohttp, and
  Tornado are parsed, but their handlers are not entry points, so no data-flow check
  starts from them. `holdout-2`'s Django cases mostly miss for this reason.
- Data flow follows calls into this project's functions and methods, including a
  function handed to a background task, thread or task queue with its arguments. A value
  one route stores in the session is followed, by key, to the routes that read it back,
  and a value a route writes to a stored record's field is followed, by field name, to
  unescaped markup and template source that read the field back. It does not follow
  other callbacks, dynamic dispatch, values kept in caches, stored data reaching any other
  sink, or decorators that rewrite a handler's arguments.
- Python dependency manifests are not compared against advisories. The offline advisory
  table covers npm only.
- XSS through a hand-built `jinja2.Template(...)` with autoescape off is not followed.
- The object-level authorisation and missing-authentication rules are heuristic and
  tuned for precision. They stay silent wherever ownership or identity could be
  established somewhere they cannot see.

## Measurement

On development data:

- `corpus-python` (56 cases): recall and precision 1.000.
- The `python-fastapi` family in `benchmark/corpus`: 5 of 5.
- The two fixtures, `vuln-fastapi` and `vuln-flask`: recall and precision 1.000 in the
  whole-product harness.

The first held-out corpus, `holdout-python` (58 cases, frozen before the engine was
developed), was scored once at `3f02017`: recall 0.821 (23/28), precision 0.852, and 4
of 30 safe cases flagged ("Python Run 1" in `docs/12-release/HOLDOUT-PROTOCOL.md`). It was
then burned on purpose: its nine misses and false positives were read and fixed
generally (cookie names bound to constants and `**mapping` flags, method attribution on
multi-method views, redirects stored in the session, host allow-lists and same-host
predicates read by shape, tuple positions for bound SQL, audit calls not taken for
ownership checks). It now reads 1.000 / 1.000 and is development data.

The second held-out corpus, `holdout-python-2` (62 cases, written blind while those
fixes were made and scored once afterwards at `15a6f63`), reports recall 0.774 (24/31),
precision 0.923, and 2 of 31 safe cases flagged ("Python Run 2"). On about 30 cases a
side the two runs' intervals overlap almost completely, so neither is better than the
other in any measurable sense. Its caveats are recorded with it:

- its classes are the engine's own scope;
- its author had read which classes Run 1 found weak.

Precision was still below the 0.95 this work targeted.

`holdout-python-2` was then burned on purpose for a second improvement round: its seven
misses and two false positives were read and fixed generally (functions handed to a
background task, stored record fields followed to unescaped markup and template source,
ownership checks read through project helpers, presence checks no longer taken for
ownership, a loaded record no longer taken for an identity check, a parsed URL's
authority alone pinning its destination). It now reads 1.000 / 1.000 and is development
data ("Python Run 2 is burned" in `HOLDOUT-PROTOCOL.md`). No other corpus moved.

**Run 2 stays the figure to quote** — as the most recent blind Python run, on a corpus
that has since been fixed against, not as a measurement of the current engine. A third
Python holdout was planned and not produced, so the next blind Python figure is pending
a new held-out set.

## Consequences

- One more workspace package and three small runtime dependencies in the CLI bundle.
  The npm tarball grows from 1350 KB to 1421 KB packed (+71 KB), and from 4671 KB to
  4875 KB unpacked (+204 KB), measured with `pnpm publish:check` against the
  integration branch before this work.
- A Python finding is indistinguishable downstream from a JavaScript one, so every
  report, export and dashboard feature works for it without change.
- A second language means a second set of framework models to keep current. Adding
  Django is the obvious next step, and it is a project-model change, not a new seam.
