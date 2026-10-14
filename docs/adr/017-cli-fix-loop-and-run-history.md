# ADR 017: A branch-per-finding fix loop, run history by fingerprint, and an honest no-agent run

Status: Accepted (0.3.0).

## Context

Four gaps in the 0.2 CLI experience:

1. `npx myrqen auto` from a plain terminal finished in about two seconds with nothing
   verified and host and model "unknown". That is correct — verification is the agent's
   job and Myrqen has no model (ADR 001) — but the CLI never said so, so it read as a
   broken scan.
2. An assessment is many short CLI calls made by the agent. No call owns the screen, so a
   person had nothing to watch.
3. The agent had to guess how to start the app under test on every run.
4. Remediation was `fix prompt` plus a self-reported `fix record --verified`. Nothing
   isolated the change, re-checked it, or kept it off the user's branch, and there was no
   way to compare one run with the next.

## Decision

**No-agent clarity.** The CLI recognises a host agent from environment variables the
hosts set (`CLAUDECODE`, the cross-vendor `AI_AGENT`, and best-effort names for Codex,
OpenCode, Gemini CLI and Cursor) or from `--agent`. It reads nothing else and executes
nothing. Without one, the first line of `auto` says only the static pass will run, and the
last names the unproven count and the exact continuation in an agent detected on the
machine by the existing filesystem-only adapter detection (`/myrqen auto` in Claude Code,
`$myrqen auto` in Codex). Verification stays agent-driven. The JSON context gains
optional `hostAgent` and `appRuntime` fields; existing fields are unchanged.

**Progress.** The eight phases fold into the five product stages (Discover = preflight,
scope, discovery, source_review; Probe = runtime_validation, access_control; Settle =
validation, reporting, or any verify/refute; Fix and Retest from `fixHistory`). A terminal
gets a small panel redrawn with hand-rolled ANSI; a pipe, `CI`, `NO_COLOR`, or `TERM=dumb`
gets one `progress …` line per change; `--json` gets nothing, so agent-captured output is
unchanged in shape. `myrqen watch` follows the session file read-only from a second
terminal. No dependency was added.

**Run configuration.** Detected once (scripts, lockfile, framework port, a port in the
script or server entry, variable *names* from `.env.example`-style templates — never
`.env`), confirmed with one question in an attended terminal or given as flags, then saved
to `.myrqen/config.json`. That file is safe to commit and is not git-excluded. Its URL must
be loopback: a config file is not the exact-origin authorization gate and cannot widen
scope.

**History.** `report` and `diff` read local sessions. Cross-run identity is category,
static rule, origin, normalized route, file, and component — not the intake fingerprint,
which hashes the summary text: on the vuln-shop fixture a one-line traversal fix made the
engine reword an SSRF summary two handlers away, and the intake fingerprint reported it as
one finding fixed and another introduced. Findings that share a location are paired in
order rather than collapsed. This sits behind a `FindingFingerprinter` interface in
`apps/cli/src/history/compare.ts`, the one place to swap in the reports package's
`createBaseline`/`compareToBaseline` when it lands; whatever replaces it must not hash
prose. A fix that comes back is `regressed`, not `new`.

**Fix loop.** `fix <id>` requires git and a clean tree (Myrqen's own state directory
excepted), creates `myrqen/fix-<id>` from HEAD, and either applies a mechanical fix or
writes a plan and prompt for the agent under `.myrqen/fixes/` (git-excluded). The only
mechanical fix is a dependency bump to the first fixed release inside the same major
version, preserving the range operator; Myrqen never runs a package manager. `retest <id>`
re-runs only the finding's static rule (all other rules disabled). A finding verified at
runtime, or found by the agent, cannot be closed by the static engine going quiet: the
agent must repeat the request and pass `--evidence` (redacted against the project's
secrets before it is stored or committed). On a pass, and only on the fix branch, Myrqen
commits everything outside its state directory with
`fix(security): <title> (<id>)` and the retest summary, marks the finding
`fixed_verified`, and rewrites a finished local report. It never pushes, resets, stashes,
or commits to another branch; git runs through `execFile` with an argv array and the commit
message goes on stdin.

## Consequences

- A first-time user is told what happened and what to do next instead of reading a fast,
  empty run as the product.
- `fixed_verified` from the loop always has a recorded, re-run check behind it. The older
  `fix record --verified` path still exists for projects without git.
- The deterministic-fix version table (`FIRST_FIXED` in `apps/cli/src/fix/deterministic.ts`)
  duplicates knowledge that belongs beside the advisory table in `packages/scan`; it should
  move there as a `fixedIn` field. *Resolved in 0.3:* the CLI now reads `fixedIn` from
  `packages/scan/src/dependencies.ts`, derived from the advisory snapshot (ADR 019).
- Host detection for agents other than Claude Code relies on variable names not yet
  checked against those vendors' documentation. A miss only means the no-agent hint is
  shown to an agent, whose step list is still printed.
