# Data model

This is the logical model. The starter Drizzle file implements a subset. Use UUIDv7/UUID/ULID consistently; do not encode tenant identity in guessable IDs.

## Identity

### users
- id
- email_normalized (unique)
- password_hash / auth-provider reference
- created_at
- status

### recovery_codes
- id
- user_id
- code_hash
- consumed_at
- created_at

### devices
- id
- user_id
- display_name
- credential_hash/key_id, never raw secret
- created_at, last_used_at, revoked_at
- client_version, OS/arch metadata

### device_link_requests
- id
- public_request_id
- secret verifier hash
- expires_at
- approved_by_user_id
- approved_at
- consumed_at

## Tenancy

### workspaces
- id
- type: personal|team
- name
- owner_user_id for personal
- plan/entitlement reference
- created_at

### workspace_memberships
- workspace_id
- user_id
- role: member|workspace_admin
- status

### projects
- id
- workspace_id
- name
- binding_public_id
- created_by
- created_at

Personal and team projects are never inferred merely from a repository name.

## Scans/reports

### reports
- id
- workspace_id/project_id/user_id
- local_report_id (idempotency key)
- state: live|finalizing|complete|failed|expired|deleted
- effort_requested/resolved
- agent_name, agent_version, model_name
- token_count, token_source: exact|estimated|unavailable
- duration_ms
- severity aggregate counts
- verification aggregate counts
- sync_created_at
- expires_at
- object_key/version
- schema_version

### report_live_events
Prefer ephemeral broker storage. Persist only minimal operational events when needed, with short retention. Never persist source/evidence in progress payloads.

### findings
POC may store findings inside encrypted report object rather than normalized rows. If normalized for search, fields must be tenant-scoped and access-controlled. Never copy finding prose into analytics.

## Sharing

### report_shares
- id
- report_id
- stable public slug/token hash
- mode
- password_hash nullable
- expires_at nullable
- revoked_at nullable
- anonymous_allowed
- redaction_profile

### share_principals
- share_id
- principal_type: user|email|workspace|anonymous
- principal_value/user_id
- projection_policy_id

### share_projection_rules
- policy id/version
- allow/deny section IDs
- allow/deny finding IDs/tags/severities as explicitly supported
- field masks for evidence/code/reproduction/remediation/metadata

## Quota

Use transactional counters or ledger rows, not client counting.

### sync_quota_ledger
- id
- user/workspace entitlement subject
- report_id/idempotency key
- quota_day_key (06:00 UTC anchored)
- quota_week_key (Monday 06:00 UTC anchored)
- state: reserved|committed|released
- created_at/committed_at

## Analytics/audit

### product_events
Strict allowlisted schema; no report prose.

### audit_events
Security-relevant actor/action/resource/reason/metadata; immutable append-only semantics.

### support_access_grants
- id
- admin_user_id
- report/workspace scope
- reason
- created_at/expires_at/revoked_at
- approved_by if policy later requires dual control.
