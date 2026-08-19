# Build status

What exists in this repository, and what is deliberately not here yet. Verified by
`pnpm test:all` on 2026-08-19. To exercise it by hand, follow
`docs/LOCAL-WALKTHROUGH.md`.

## Delivered

### Agent runtime and CLI

- Portable Agent Skill in `packages/skill/myrqen`, installed to the locations Claude
  Code, Codex, OpenCode, and portable agents actually read. Backs up any directory
  Myrqen did not write; reinstalling an unchanged bundle is a no-op.
- `myrqen low|high|xhigh|ultra|auto`, `session start|context|sync-decision|agent|finish|cancel`,
  `phase`, `target authorize|check|redirect`, `action check`, `finding submit`, `note`,
  `metrics token`, `fix prompt|record`, `link`, `install`, `status`, `logout`,
  `workspace`, `reports`, `sync`, `doctor`, `update`, `config`, `skill`.
- Effort resolution from real project signals; `auto` records the resolved profile and
  its rationale.
- Exact-origin authorization, redirect gating, private-network classification, planned
  action classification, and prompt-injection detection, all enforced by the CLI rather
  than trusted to the agent. An origin proposed only by content that also tries to
  instruct the scanner is quarantined and cannot be authorized at all, so untrusted
  content cannot widen scope even by persuading a human.
- The isolated-runtime probe can never stall a scan: an unresponsive daemon is killed
  and reported as unavailable.
- Finding intake with schema validation, redaction, severity normalization, stable ids,
  fingerprint deduplication, and corroboration merging.

### Reports

- Canonical schema-validated report, plus offline HTML, Markdown, JSON, and SARIF.
- The HTML artifact makes no network request of any kind, filters by severity and
  verification, and carries a copy-prompt-to-fix control per finding.
- Coverage and limitations are always present; an empty report states explicitly that
  it is not evidence of security.

### Cloud

- Email and password accounts with recovery codes and no outbound email.
- Browser-approved device linking with a one-time exchange, hashed credentials, OS
  keystore storage, and a permission-restricted fallback.
- Per-scan sync decision, quota-gated, with an immediate live report URL and
  privacy-safe SSE progress.
- Free quota of 5 per quota day and 15 per quota week, anchored at 06:00 UTC and Monday
  06:00 UTC, with transactional reserve, commit, release, and stale reconciliation.
- 21-day retention enforced by the worker: object deleted, shares revoked, live events
  pruned, audit event written, local files untouched.
- Server-side share projections: one URL, different reports per principal, with
  password, expiry, revocation, anonymization, and per-finding field masks. Exports use
  the same projection.
- Platform admin analytics with no report content, and break-glass report access behind
  a reasoned, expiring, audited grant.

### Quality gates

- 233 automated checks: 188 unit and database-integration tests across the packages,
  plus a 45-step acceptance journey run against a real server, a real database, a real
  encrypted object store, and the built CLI binary.
- Benchmark harness over owned fixtures: recall 1.00 and precision 1.00 on `vuln-shop`
  (12 ground-truth issues), zero false positives on `safe-app`, zero safety violations,
  zero canary leaks.
- Signed-update pipeline with key generation, manifest signing, and client verification
  covering bad signatures, unknown keys, schema violations, stale and future manifests,
  digest mismatches, downgrades, pins, and revocations.

## Not built yet, and why

| Area | Status | Reason |
| --- | --- | --- |
| Branded PDF export | Deferred | `docs/05-reporting/REPORT-SCHEMA.md` permits deferring until a robust renderer exists. The HTML report carries a print stylesheet with `@page` margins, so browser print-to-PDF produces a usable document today. |
| Team invitations | Partial | Team workspaces, roles, membership, and workspace-scoped reports work. Invitations need email delivery, which is an explicit POC non-goal; members are added by user id through the API. |
| GitHub and Google sign-in | Not started | Explicit POC non-goal. |
| Windows and Linux verification | Untested here | The code paths exist (DPAPI through PowerShell, `secret-tool`, platform config directories) and are unit tested where they are pure, but this build was verified on macOS arm64 only. |
| Valkey fanout driver | Not needed yet | PostgreSQL LISTEN/NOTIFY covers cross-instance delivery for the POC. The `EventBus` interface is the seam. |
| Third-party vulnerable corpora | Not vendored | Only Myrqen-owned fixtures are present. Adding one requires a licence and redistribution entry in `IP-PROVENANCE.md` first. |
| Model-versus-model benchmarking | Harness ready | `benchmark/run.mjs` scores any agent that drives the CLI. Comparing real models over the same fixtures is a separate exercise. |
| Pricing and checkout | Deliberately absent | Entitlements are policy data in `packages/entitlements`; no pricing surface exists. |

## Known operational gaps before production

1. `REPORT_ENCRYPTION_KEY` is an environment secret. Move it to a KMS and document
   rotation before any real customer data exists.
2. Rate limiting is process-local. It blunts abuse in a single instance; a shared
   limiter belongs behind the same interface before scaling out.
3. No release signing key is embedded in this build, so `myrqen update` reports that no
   signed channel is configured rather than trusting anything.
4. Backups and the retention tombstone replay described in `docs/10-ops/EU-DEPLOYMENT.md`
   are documented but not exercised.
