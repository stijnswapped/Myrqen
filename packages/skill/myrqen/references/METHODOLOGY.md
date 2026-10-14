# Assessment methodology

Combine source reasoning with controlled runtime validation. Depth comes from the
resolved effort profile in the session context; the rules never change.

## Phase 0 — preflight

Identify the repository root and stack. Load the Myrqen session context. Detect a
local test or development runtime without mutating any production configuration.
Inventory local origins and the external origins the project references. Identify the
available test identities and safe fixtures. Note whether an isolated runtime is
available, and say so calmly if it is not.

## Phase 1 — application map

Build a threat-oriented map before looking for bugs:

- entry points, routes, and endpoints;
- authentication and session implementation;
- roles and where authorization is enforced;
- data stores and trust boundaries;
- file upload and download surfaces;
- server-side outbound requests and webhooks;
- parsing, deserialization, template rendering, and query construction;
- secret and configuration handling;
- administrative or internal endpoints;
- third-party integrations;
- dependency manifests and lockfiles.

### The value and trust model

A map of routes finds injection. It does not find the bug where a customer pays
themselves. Before Phase 2, write down — for yourself, not for the report:

- **What is valuable here.** Money, credit, quota, access, published state,
  someone else's data.
- **Who owns each valuable thing**, and which column or claim expresses that.
- **The roles**, and what each is allowed to do that the one below cannot.
- **The trust boundary of every value the server uses**: which came from the
  caller, and which the server computed or looked up. A price, a quantity, a
  discount, a role, an owner id, a status, and a total each belong on one side of
  that line, and the defect is almost always a value that crossed it.
- **The state machine** of anything that moves through stages: draft to approved,
  pending to paid, invited to member. Note which transitions are supposed to be
  one-way and who may cause each one.

### Attack hypotheses

From that model, write specific hypotheses before reading for bugs. Each one is a
question with a yes or no answer, about this application:

- Can account A read, change, or delete account B's object by changing an id?
- Can a normal user reach an operation only an administrator should reach?
- Can the caller choose a value the server is supposed to decide — a price, a
  discount, a total, a role, an owner, a tenant, a status?
- Can a state be skipped: paid without paying, approved without approval,
  published without review?
- Can a one-time thing be used twice — an invitation, a coupon, a reset link, a
  refund, a redemption?
- Can a quantity be negative, zero, or absurdly large, and does the result still
  make sense?
- Can two concurrent requests both succeed where only one should?
- Does anything trust a value the client computed?
- Does any check happen after the effect it is supposed to prevent?

Carry every hypothesis into Phase 2 and Phase 3 and settle it. A hypothesis you
could not settle is a limitation and belongs in the report as one; silently
dropping it is the difference between an assessment and a demo.

## Phase 2 — source, configuration, and dependency review

Myrqen has already run its own static pass by the time you read this, so start by
reading its candidates rather than the file tree:

```bash
myrqen finding list
```

Each one names a class, a severity, a route or file, and — where the rule could state
one — how to exercise it. They come back unsettled first, because the candidate nobody
has exercised is the one worth your attention. Reading the list changes nothing, so
read it as often as you like; `myrqen session static-pass` is a different thing and
re-runs the analysis. Your value is in the two things it cannot do: follow a
value across module boundaries, and observe what the running application actually
returns.

Then look for plausible root causes it could not reach, not keyword matches:

- credentials committed or exposed through a route;
- insecure defaults and configuration;
- authorization missing at a server-side boundary;
- unsafe composition of queries, commands, templates, or paths;
- insecure file handling and path containment;
- server-side fetches without destination validation;
- token, cookie, and session mistakes, including entropy and expiry;
- trust in client-controlled role or ownership identifiers;
- dependency versions inside a published advisory range, with reachability recorded
  honestly as uncertain when it is;
- debug or administrative exposure;
- security-relevant business-logic assumptions.

## Phase 3 — controlled dynamic validation

Prefer the local running service. Exercise routes with representative safe inputs and
the configured test identities. The goal is to establish whether a candidate is
actually reachable and security-relevant. Stay inside the authorization and safety
rules; gate anything risky through `action check` first.

Settle every static candidate here. `myrqen finding verify <id> --description "<what
you requested and what came back>"` raises it to `verified`; `myrqen finding refute
<id> --reason "<what you tried and what happened instead>"` records that you could not
reproduce it. A candidate left unsettled stays `needs_review` in the report, which is
the honest outcome when the service was not running — say so as a limitation rather
than leaving the reader to guess.

### Starting a Python app

Myrqen detects how to start a Node app from `package.json`. For a Python app it
usually cannot, so `appRuntime` is absent and you start the app yourself. Use the
project's own instructions first (README, `Makefile`, `Procfile`, `docker-compose.yml`).
Without them:

- **FastAPI**: find the `FastAPI()` instance and serve it with uvicorn, for example
  `uvicorn app.main:app --host 127.0.0.1 --port 8000`. A factory needs `--factory`.
- **Flask**: `flask --app <module> run --host 127.0.0.1 --port 5000`, or the
  project's `run.py`. Do not turn on `--debug`: it serves the Werkzeug debugger, an
  interactive Python console on every error page, guarded only by a PIN.

Use the project's virtual environment. If its dependencies are not installed, ask the
user before installing anything. Bind to `127.0.0.1` only, and then save the command
with `myrqen config set run.command` and `run.url` so the next run starts the same way.
Django, class-based views, aiohttp and Tornado handlers are not entry points for the
static pass, so in those apps your own route mapping in Phase 1 carries more of the
assessment.

## Phase 4 — access-control matrix

With the identities available, compare:

- unauthenticated;
- normal user A;
- normal user B, for object-ownership boundaries;
- an administrative or privileged test user.

Focus on server-side enforcement and object ownership, using non-destructive fixture
objects. When a class cannot be tested because an identity or fixture is missing,
record that as a limitation rather than guessing.

## Phase 5 — validation and deduplication

Assign verification honestly:

- `verified` — deterministic local or authorized evidence demonstrates the issue;
- `strong_evidence` — the root cause and a reachable path are strongly supported, but
  full proof is unavailable or unsafe;
- `needs_review` — plausible, with insufficient validation.

Severity reflects realistic impact in this application, not the reputation of the
category. Submit alternate evidence for the same root cause as another submission;
Myrqen merges it as corroboration.

### The challenge pass

The reasoning that invents a candidate must never be the reasoning that confirms
it. For every finding you are about to report at `high` or above — and for every
`critical` or `high` finding at any effort — take the opposite side explicitly:

> Assume this candidate is false. Try to prove the application is actually safe.

Then go looking for the thing that would make it safe: a guard in middleware two
files away, a database constraint, a framework default, a check in a base class,
an allow-list, a type that cannot hold the dangerous value, a branch that is
unreachable in production. Record what you looked for and did not find — that
search is the evidence, and it is what separates a finding a developer acts on
from one they argue with.

Only after that pass, classify. A candidate that survives it with runtime proof is
`verified`; one that survives on a clear path with no safe runtime proof available
is `strong_evidence`; one you could not settle either way is `needs_review`. Do
not let a candidate keep the confidence its author gave it.

## Phase 6 — remediation

For each actionable finding: name the root cause, propose the smallest durable fix,
prefer the framework's own safeguard, and name the regression or security test that
would fail before the fix and pass after it. Avoid broad rewrites.

## Phase 7 — apply and verify

Only after the user chooses to apply: change the source, run the project's targeted
tests, re-run the specific security validation, and mark the finding fixed only if
that validation actually passes. Preserve the original evidence and the remediation
history either way.

## Coverage honesty

Every report states what was not assessed and what could not be validated. `ultra`
is deeper, not omniscient. Never claim a system is secure because no findings were
produced.
