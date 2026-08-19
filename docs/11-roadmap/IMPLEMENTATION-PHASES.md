# Implementation phases

These are dependency phases, not calendar promises. The coding agent should continue across them until acceptance is met.

## Phase 0 - repository integrity

- validate current stack versions from primary docs;
- establish monorepo build/lint/test;
- implement brand/contracts/policy packages;
- migrations/dev environment;
- CI baseline;
- ADR discipline.

Exit: clean install/build/typecheck/test.

## Phase 1 - complete thin vertical slice

- email/password auth + recovery codes;
- device linking and CLI credential store abstraction;
- workspace/project binding;
- `myrqen auto` session lifecycle with a simple safe assessment fixture;
- local canonical report + HTML/JSON/Markdown;
- sync decision/quota/report shell/live SSE;
- finalized cloud report view.

Exit: real end-to-end flow on one host/OS.

## Phase 2 - security depth

- portable Agent Skill and Claude/Codex/OpenCode adapters;
- methodology phases;
- multiple test identities;
- external authorization policy;
- finding validation/dedupe;
- dependency/config/secret/source/runtime checks;
- copy/apply/verify workflow;
- SARIF/PDF.

Exit: benchmark corpus catches meaningful ground truth with no policy violations.

## Phase 3 - sharing and team semantics

- share ACL/projection engine;
- principal-specific same-link views;
- password/expiry/revoke/anonymous/redaction;
- projected exports;
- team workspace/admin flows;
- audit.

Exit: leakage tests pass.

## Phase 4 - product intelligence and operations

- analytics taxonomy ingestion;
- admin funnel/model/effort/token/time views;
- break-glass support access;
- retention worker;
- signed updater/version governance;
- system health and sanitized errors.

Exit: operator can run product without reading customer reports.

## Phase 5 - cross-platform and polish

- macOS Apple Silicon/Intel where supported;
- Windows native;
- Linux;
- WSL;
- install/doctor/update compatibility;
- performance and accessibility;
- product copy/onboarding;
- backup/deletion failure drills.

Exit: `docs/09-testing/ACCEPTANCE-TESTS.md` passes.
