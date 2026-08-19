# Free sync quotas and retention

## Free limits

Both apply:
- 5 successfully created cloud reports per quota day.
- 15 successfully created cloud reports per quota week.

Whichever limit is reached first blocks additional report creation until the relevant reset.

## Anchors

Quota day boundary: 06:00:00 UTC.
Quota week boundary: Monday 06:00:00 UTC.

Do not calculate boundaries using user locale/daylight savings.

## What counts

One cloud report successfully created/accepted = one sync unit. Opening, sharing, exporting, commenting, or retesting inside the same report concept does not independently consume a new sync unless product semantics explicitly create a new report.

Use local report ID/idempotency key to stop retry duplication.

## Reservation semantics

Avoid charging users for failed network attempts:
- transactionally reserve capacity when creating a report;
- commit when report shell creation succeeds according to contract;
- release stale failed reservations;
- make retries idempotent.

## Limit UX

When blocked, the scanner still completes and stores locally. Show concise wording, for example:

`Cloud report limit reached. This scan will stay local. You can try "myrqen sync <report-id>" after Monday 06:00 UTC.`

Do not ask "Sync this scan?" when it cannot succeed. Do not auto-sync at reset.

## Retention

Free cloud report expiry = `sync_created_at + 21 days`.

At/after expiry worker:
1. marks report expired/deleting;
2. invalidates share access;
3. deletes report object/evidence/derived exports;
4. removes/irreversibly deletes normalized report content according to schema;
5. retains only minimal lawful/operational tombstone/aggregate data that does not reconstruct report content;
6. writes deletion audit event.

Local files are not touched.

Paid plans may extend/configure retention later through entitlement policy, not hard-coded branches throughout the app.
