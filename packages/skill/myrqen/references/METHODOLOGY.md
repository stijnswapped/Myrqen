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

## Phase 2 — source, configuration, and dependency review

Myrqen has already run its own static pass by the time you read this, so start by
reading its candidates rather than the file tree. Each one names a route, a line, and
the data flow it believes in. Your value is in the two things it cannot do: follow a
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

At `high` effort and above, run a false-positive challenge pass: for each candidate,
argue the opposite and keep only what survives.

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
