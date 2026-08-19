# Cloud sync and live report protocol

## Decision timing

Ask sync before assessment only when quota is available. If over daily/weekly quota, show limit/reset once and proceed locally without a sync prompt.

## Creating live report

After user says yes:
- create report shell using local report ID as idempotency key;
- atomically reserve/commit quota so duplicate retries do not create duplicate reports;
- return cloud report ID and normal browser URL immediately;
- open URL if UX supports it, but scanning does not depend on browser being open;
- begin authenticated privacy-safe progress stream.

## Progress event allowlist

Schema in `schemas/scan-event.schema.json`.

Allowed event types:
- report_created
- phase_started
- phase_completed
- aggregate_updated
- warning_safe
- scan_completed
- scan_failed

Payload fields are intentionally limited to phase ID, timestamps, durations, safe count metrics, effort/agent/version metadata, and predefined/sanitized status code/message.

Never accept a generic arbitrary JSON blob from the scanner as analytics/progress.

## Authentication

Device credential authenticates API caller. Report-ingest capability is scoped server-side to account/project/report. Use replay-resistant idempotency/event IDs. Rate limit per device/report.

## Browser realtime

Browser uses web session and ordinary report authorization. SSE route subscribes to report events. It must reauthorize report access before connection and handle revoked access.

## Finalization

Upload final canonical report/evidence using short-lived scoped upload. API validates schema version/hash/size limits and report ownership before state becomes complete.

## Failure behavior

Network/cloud failure never invalidates local report. Preserve a retryable local sync state and show `myrqen sync <id>` as explicit recovery. Never auto-sync later.
