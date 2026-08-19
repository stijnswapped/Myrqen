# Scan protocol

## State machine

`created -> preflight -> scope -> discovery -> assessment -> validation -> reporting -> complete`

Exceptional states: `cancelled`, `failed`, `policy_blocked`.

Cloud state is separate: `not_requested`, `quota_blocked`, `live`, `finalizing`, `synced`, `sync_failed`.

## Start

`myrqen session start --effort auto`

CLI returns structured session context containing:
- session/report local ID;
- project/workspace binding;
- requested/resolved effort policy;
- allowed local target patterns;
- authorized external targets already approved for this project/session;
- prohibited actions;
- local artifact paths;
- sync state/live report URL if applicable;
- host metadata collection instructions.

## Sync decision ordering

1. User is authenticated/linked.
2. Resolve project/workspace.
3. Check cloud report quota.
4. If quota unavailable: print concise limit/reset information; do not ask sync; cloud state = quota_blocked.
5. If quota available: ask once whether to sync this scan.
6. If no: cloud state = not_requested; no live cloud event channel.
7. If yes: create cloud report shell atomically and return URL immediately.

## Finding submission

Agent submits structured finding to local CLI, ideally JSON on stdin. CLI:
- validates schema;
- rejects raw secrets where detectable;
- normalizes severity/category;
- assigns stable local finding ID;
- computes dedupe fingerprint from category + normalized target/location + root cause/evidence identity;
- preserves alternate evidence as corroboration rather than duplicate finding;
- records verification state.

## Progress

Only for synced scans. Allowed examples:
- phase_started/phase_completed;
- coarse target/service count;
- aggregate candidate/validated finding counts;
- safe status text selected from server/CLI allowlist;
- timing.

Forbidden:
- source code;
- report prose;
- raw prompts;
- secret values;
- raw request/response bodies;
- PoC payloads;
- credentials;
- unredacted external URLs if product policy classifies them sensitive (store normalized origin only when necessary).

## Finish

CLI validates that findings are structurally complete, records limitations/coverage, generates local formats, and finalizes cloud report if sync was chosen.

If cloud finalization fails, preserve the complete local report and a retryable manual sync state. Do not delete or corrupt local results.

## Manual later sync

`myrqen sync <local-report-id>`
- verify report exists and schema is supported;
- recheck login/device and quota;
- explicitly identify destination workspace/project;
- upload/finalize;
- never auto-run after quota reset.
