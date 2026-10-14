# ADR 021: Finding triage is per project and fingerprint, separate from verification

Status: Accepted (0.3.0).

## Context

A synced report says what one scan observed. The people responsible for the project then decide what each finding means for them: it is real and being fixed, real and deliberately accepted, not a vulnerability here, or done. Before 0.3 the dashboard had nowhere to record that, so every rescan presented the same findings as new work, and the only "status" was the report's own `status` field, which the CLI owns and which a dashboard user cannot change.

## Decision

**Model.** Triage is stored in `finding_triage`, keyed by `(project_id, fingerprint)` — not by report. A decision made on one scan applies to every later scan of the same project that reports the same finding. Four states: `open`, `accepted_risk`, `false_positive`, `fixed`. Comments live in `finding_triage_comments` under the same key. Migration `0003_finding_triage.sql` (generated, ADR 013).

**Invariants, enforced by the database as well as the application.**

- `accepted_risk` and `false_positive` require a non-blank reason (`finding_triage_reason_ck`); reasons are at most 1,000 characters.
- `accepted_until` exists only on `accepted_risk` (`finding_triage_expiry_ck`). The application caps it at three years and requires a future date.
- Comments are 1–2,000 characters of plain text, rendered as React text with `white-space: pre-wrap`. They are never parsed as markup.
- An assignee must be an active member of the project's workspace, checked in the same transaction as the write.

**Effective state is computed, not stored.** What the reader sees can differ from what was saved, and the dashboard says why:

- an accepted risk past its `accepted_until` reads as **open** ("Risk acceptance lapsed on …");
- a finding marked **fixed** before a scan that still reports it reads as **open** ("Marked fixed on …, but this later scan still reports it"). The comparison uses the server's `sync_created_at`, not an agent-supplied timestamp.

Verification and triage stay independent axes, like severity and verification. A human's "fixed" is never shown as a verified fix: only the report's own `fixed_verified` moves a finding to "No longer open". A human's "false positive" does move it there, the same way the report's own `false_positive` status does. Non-open triage removes a finding from the remediation queue.

**Fingerprint.** `apps/web/lib/triage-fingerprint.ts` is the single function that decides identity: `tf1_` + SHA-256 over the finding class, origin, route with concrete ids collapsed (`normalizeRoute` from `@myrqen/policy`, with the HTTP method kept), and normalized file path. The component name is used only when there is neither a file nor a route, because it is agent-worded. Line numbers are excluded because they move on every edit above the finding. The CLI's own `finding.fingerprint` is deliberately *not* used: it includes the agent's summary prose, which changes wording between runs. When `packages/report` ships baseline fingerprints (`createBaseline` / `compareToBaseline`) in the synced report, swap the body of that function and bump the prefix; rows under an old prefix stop matching rather than attaching to a different finding. Known cost: two findings of the same class at the same file and route share one decision.

**Authorization.** Every write is a server action that authenticates the session, rate-limits per account (`LIMITS.triage`, 60 per minute), and calls `authorizeTriage`, which takes only a report id and a finding id from the client. It requires report access (owner or workspace member, not expired) **and** active membership of the project's workspace, loads the stored report, finds the finding, and derives the project and the fingerprint itself. A client cannot name a project or a fingerprint, so a decision cannot be written onto a project the caller cannot read. Every refusal returns the same sentence. Triage is never part of a share projection; the share viewer does not receive it.

**Plans** (`packages/entitlements`):

| Capability | Free | Pro | Team | Enterprise |
|---|---|---|---|---|
| `findingTriage` — state, reason, expiry, filters, counts | yes | yes | yes | yes |
| `triageCollaboration` — assignee, comments, visible history | — | — | yes | yes |

State and reason are on every plan because deciding what a finding means for your own project is part of reading it, and findings are never paid content. Assignment and discussion only mean something with more than one person, so they follow team workspaces. The audit row (`audit_events`, `resource_type = 'finding_triage'`, `resource_id = '<project>/<fingerprint>'`) is written on **every** plan, in the same transaction as the change — reasons go in the `reason` column, comment text never enters the audit trail (only its id and length). Only the per-finding history *display* is a Team feature.

## Consequences

- Rescans stop re-presenting decided findings as new work, without the CLI or the report format changing.
- A lapsed acceptance or a contradicted fix cannot keep implying safety nobody chose.
- Moving to the report package's baseline fingerprint is a one-function change with an explicit, non-silent cut-over.
- Deleting a project cascades its triage and comments; deleting a user keeps their decisions and comments with the author shown as "a former member".
