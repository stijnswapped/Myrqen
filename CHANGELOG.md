# Changelog

Every release of the `myrqen` CLI, and what changed about **detection** in it,
because that is the part a user of a security tool is actually trusting.

Detection numbers are quoted with the corpus they came from. A number without its
corpus is meaningless: the development corpus was tuned against and reads 1.000,
which says nothing about code nobody has seen. See
<https://myrqen.cc/benchmarks> for the methodology behind all of them.

This project does not follow semantic versioning strictly yet, because there is
no stable public API to version — the CLI's JSON output and the finding schema are
the closest thing, and both are versioned in `schemas/`.

## Unreleased

Nothing yet.

## 0.3.0 — 2026-10-14

Reports that open with a verdict, a fix loop that branches, commits and retests,
Python for FastAPI and Flask, cross-module data flow, and reachable dependency
advisories.

**Detection** (as measured on 2026-10-14; the static pass alone)

| Corpus | Recall | Precision | Safe-case false positives |
|---|---|---|---|
| `holdout-7`, newest blind JS/TS corpus (CWE-matched) | 0.250 | — | 4/32 |
| `holdout-3`, burned, after the fixes it prompted in 0.2.0 | 0.500 | 1.000 | 0/34 |
| `holdout-python-2`, blind, scored once before the last round of Python fixes | 0.774 | 0.923 | 2/31 |
| `corpus` (development, tuned against) | 1.000 | 0.989 | 1/91 |

The gate is recall 0.90 and precision 0.95. Recall misses it on every held-out
corpus, and Python precision is below it; a new blind Python measurement follows
in 0.3.x.

- JavaScript and TypeScript data flow crosses modules where a call resolves, up to
  four calls deep; zod/yup/joi/valibot schemas and framework-decorated parameters are
  understood. On the corpora this moved one case (a holdout-2 detection credited to
  the right route).
- Twelve new rule shapes (DOM XSS, open redirects, HTML reflection, mass assignment,
  JWT misconfiguration, credentialed any-origin CORS, unthrottled credential routes,
  prototype pollution paths, interpreter-argument command injection, unsafe
  deserialization libraries, NoSQL aggregation injection).
- Dependency advisories from an offline OSV/GitHub snapshot, resolved from the
  lockfile and reported only where application code calls an affected export.
- Python: FastAPI and Flask routes, auth dependencies and blueprints, with taint
  across project modules, for thirteen vulnerability classes.

**Reports.** A verdict and "fix these first" up front; one source of truth for every
count across all four formats; CWE / OWASP Top 10 2021 and 2025 / ASVS references;
`.myrqen/baseline.json` for new-versus-known findings.

**CLI.** `myrqen fix <id>` and `myrqen retest <id>` (own branch, commit on pass,
never pushes); live progress; `report`, `diff`, `watch`; a remembered app start
command; a clear message when no agent is driving the run.

**Dashboard.** Triage that carries across scans, a plan and billing page with
checkout, a rebuilt interface, the verdict and compliance in the browser.

**Not in this release.** Java, Ruby and Go are not parsed; Python routes only for
FastAPI and Flask. No destructive testing at any effort.

## 0.2.0 — 2026-08-21

The first release worth installing. `npm install -g myrqen`, or
`npx myrqen@latest`.

**Detection**

| Corpus | Recall | Critical/high | Precision | Safe-case false positives |
|---|---|---|---|---|
| `holdout-3`, scored blind before any change | 0.294 | 0.294 | 0.833 | 0.059 |
| `holdout-3`, after the nine changes it prompted | 0.441 | 0.441 | 1.000 | 0.000 |
| `corpus` (development, tuned against) | 1.000 | 1.000 | 1.000 | 0.000 |

The gate is recall 0.90, critical/high recall 0.95, precision 0.90, safe-case
false-positive rate 0.03. **Precision and the false-positive rate meet it on
every corpus. Recall does not.** Of `holdout-3`'s 34 vulnerable cases, six cross a
module boundary, which the static pass states it does not follow, so a perfect
result on everything else reaches about 0.765.

- Four scanner fixes, three of them precision. `relative()`-based containment now
  counts as a guard; a producing helper still counts through `.toString()` and a
  ternary; a CORS origin predicate anchored at a label boundary gates the
  reflection; and a fluent query-builder chain — Drizzle, Kysely — is recognised
  as a record lookup. Ten regression tests, each asserting that the guarded form
  is silent *and* its unguarded sibling is still found.
- Entry-point adapters per framework: Astro, Bun, Deno, desktop CLI, editor
  extension, Nest, Nitro, realtime, serverless, SvelteKit, TanStack/Solid, and
  Cloudflare Workers.
- Prepared statements, route verbs, injection and traversal attribution, and a
  fluent-builder read-modify-write on a balance are all read correctly where they
  previously were not.

**The CLI**

- **A failing API no longer kills a scan.** `resolveBinding` called
  `client.workspaces()` and `client.createProject()` unguarded, so a linked device
  plus an unreachable API threw out of `session start`: exit 1, no report, even
  though scanning needs no network. Both now degrade to the local outcome an
  unlinked device gets, and name the reason. Covered by
  `apps/cli/test/offline-resilience.test.mjs`.
- Thirteen agent integrations, each verified against that vendor's own
  documentation with the date recorded in the adapter.
- `--scope` on `unlink`, so removing a project integration cannot reach a global
  one. This exists because an unscoped `unlink` once deleted a real
  `~/.claude/skills/myrqen` during development.
- Packaging: a single self-contained bundle with no runtime dependencies, a
  README and a LICENCE in the tarball, and no sourcemap. Nine files, 1.33 MB
  packed. `scripts/verify-tarball.mjs` installs the packed tarball into an empty
  project and runs a full link and unlink round trip under npm, pnpm, and Bun.

**The hosted service**

Deployed, and verified end to end against production: signup, browser-approved
device link, a scan, `--sync yes`, `session finish`. An unauthenticated approval
was refused 401; a non-member reading the report got 404 rather than 403, so they
do not learn it exists; a principal-scoped share showed an outsider exactly 2 of
14 findings with nothing withheld leaking; both planted canary secrets appeared in
neither the cloud copy nor the local report; and the durable device credential
never reached the terminal.

**Not in this release**

- Paid plans cannot be bought. Checkout is not configured.
- Python, Java, Ruby, and Go are not parsed at all.
- No destructive testing, at any effort. There is no opt-in flag.
- No container image has been built and verified locally.

## 0.2.0-rc.1 — 2026-08-21

The release candidate for the above, published to the `next` dist-tag so that a
plain `npm install myrqen` would not pick it up. Functionally 0.2.0; its README
carried an over-cautious statement that the hosted service was not deployed, which
was true when it was written and false a few hours later.

## 0.1.0 — 2026-08-18 — deprecated

Published from a tree that predates the packaging work and the entry-point
adapters, so it is worse on every axis including detection. It shipped no README
and no LICENCE, declared no licence or repository, and included its sourcemap.
Deprecated on npm in favour of 0.2.0. Do not install it.
