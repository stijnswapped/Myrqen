# ADR 019: Dependency advisories from an offline snapshot, reported by reachability

Status: Accepted (0.3.0).

## Context

Until 0.3 the dependency check compared the version ranges declared in `package.json`
against a nine-entry table bundled with the scanner. It had three defects that made its
output hard to act on:

1. **It read the wrong version.** A declared `^4.17.11` says nothing about what is
   installed; the lockfile does. A range that the installer resolves to the fixed release
   was reported as vulnerable, and a transitive package was never seen at all.
2. **It could not tell installed from used.** Every match was the same finding, capped at
   medium because the scanner had no way to know whether the vulnerable function was ever
   called. A project with forty stale transitive packages and one called `_.merge` on
   request data got forty-one findings of the same weight.
3. **Nine entries is not a dataset.** It went stale silently, and the CLI kept its own
   copy of the first fixed versions (`FIRST_FIXED`, ADR 017) that could drift from it.

Myrqen is local-first (ADR 002) and its static pass is deterministic (ADR 012): the same
tree must produce the same report, with no network call during a scan. That rules out
querying an advisory service at scan time.

## Decision

**Installed versions come from the lockfile.** `packages/scan/src/dependencies/lockfiles.ts`
parses package-lock v1 to v3, pnpm-lock v5, v6 and v9, yarn classic and Berry, and
`bun.lock`, by hand, so the scanner keeps no runtime dependency. Without a lockfile, a
declared spec counts as affected only when it is an exact pin, or a range that cannot
resolve past the advisory's fix (`declaredRangeCertainlyAffected`). A range that might
resolve to the fix is not reported, and the coverage notes say how many were skipped and
that committing a lockfile would settle them.

**Advisories come from an offline snapshot.** `pnpm advisories:update` queries OSV (GitHub
Advisory Database records, CC-BY-4.0) for every package in
`packages/scan/advisories/watchlist.json`, keeps the raw records in `osv-records.json`, and
generates `packages/scan/src/dependencies/advisory-snapshot.ts`, which is committed and
bundled. It is the only code that fetches advisory data, and a person runs it, never a
scan. The output is byte-deterministic for given inputs; `pnpm advisories:check`, run in CI,
rebuilds it offline from the committed cache and fails when the committed module is not
what the committed inputs produce. A test asserts that a
scan makes no network request.

The watchlist is deliberately a fixed list of commonly used packages (128 at the time of
writing), not the whole npm advisory database. A package outside it is not checked, and the
documentation says so. This keeps the bundle small and keeps every reachable advisory
curated (below); it is not software composition analysis and is not described as such.

**A finding requires reachability.** OSV does not say which function in an npm package holds
the vulnerable code. `packages/scan/advisories/reachability.json` curates that per advisory:
the module `exports` (`merge` for `_.merge`, `default` for a module that is itself the
function), the `subpaths` that are the same code (`lodash/merge`), or, more weakly, the
`members` — method names on an object the package returns. The update script names any
curated id that matches no advisory, so a refresh cannot silently orphan the curation.

`packages/scan/src/dependencies/usage.ts` records, during the scan's normal parse, which
package exports application code uses and where: imports and requires bind local names to
a package, a referenced named binding uses that export, a module binding uses `default`
when called and `x` when `.x` is read off it, and a subpath import is recorded as the
subpath. Its specification is intentionally narrow so the engine's cross-file call graph
(ADR 018) can replace it without changing the dependency check's contract.

Two kinds of candidate result:

- **`dependency-advisory-reachable`**, at the first call site, only where a curated export
  or subpath of an advisory that applies to the installed version is used. Its severity is
  the advisory's, capped at **high**, because calling the function is necessary for the
  published impact but not sufficient: whether request data reaches it is not established.
  A match on a method name alone is capped at **medium**. Verification is `needs_review`.
- **`dependency-advisory`**, one informational item at `package.json` listing every affected
  package that is present but not reached, with the reason per package (declared but not
  imported; installed by another package; imported but the affected functions are not
  called; imported but reachability for that advisory is not curated). Severity is **low**
  when any runtime package is listed and **info** when all are development-only. It is
  never dropped, because a reader deciding whether to upgrade needs it, and never ranked
  beside a reachable defect, because a reader deciding what to fix first needs that too.

"Not reached" means this scan found no path from the application's own imports, not that
no path exists. The summary says so in those words.

**One source for the fixed release.** `fixedIn(name, version)` in
`packages/scan/src/dependencies.ts` derives the first release outside every advisory range
from the snapshot: it takes the highest `fixed` bound among the ranges the installed version
is in, and repeats in case that release falls inside another advisory's range. Where a range
has no published fix, a small fallback table (the former CLI `FIRST_FIXED` values) is used
only if the snapshot confirms the fallback clears every range. The release is stated in the
finding's evidence and remediation, and the CLI's deterministic fix (ADR 017) reads the same
function rather than keeping its own table. The CLI still refuses to cross a major version
mechanically.

## Consequences

- A dependency finding now means "an affected version is installed and application code
  calls the affected function", which is worth ranking with the rest of the report. The
  supply-chain picture is still complete, in one low-severity item.
- Severity of a reachable dependency is capped below the advisory's own critical rating.
  This understates a case where request data demonstrably reaches the call; that
  confirmation is the host agent's job, and it may raise the severity with evidence.
- Curation is ongoing work. An advisory without curated reachability is never reported as
  reached, so a missing entry costs recall, not precision. The watchlist and the curation
  grow together.
- The snapshot ages between releases. Every dependency finding names its newest record date,
  so a reader can see how old the data is. Refreshing it (`pnpm advisories:update`) is a
  manual step before a release; nothing refreshes it automatically.
- Calls made by one dependency into another (express's own use of `qs`) are not followed.
  Those packages are listed as installed by another package, not as safe.
- Without a lockfile, ranges that may already resolve to a fix are not reported. This
  trades a few missed stale installs for no longer reporting projects that are already
  patched; the coverage note tells the user to commit a lockfile.
- The bundle grows by the snapshot (about 0.35 MB of generated source for 915 advisories);
  a scan never touches the network for it.
