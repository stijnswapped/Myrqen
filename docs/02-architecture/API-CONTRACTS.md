# API contracts

Use `/api/v1` for POC. APIs must be idempotent where retries are normal. Prefer typed request/response contracts from `packages/contracts` plus runtime validation.

## Device link

`POST /api/v1/device-links`
- unauthenticated bootstrap with verifier/challenge design
- returns public request ID, browser approval URL, expiration

`POST /api/v1/device-links/:id/approve`
- browser session required
- body: device display name / optional context
- records explicit approval

`POST /api/v1/device-links/:id/exchange`
- requires link verifier/proof
- one-time exchange
- returns scoped device credential exactly once

## Workspace/project

`GET /api/v1/workspaces`
`POST /api/v1/projects`
`GET /api/v1/projects/:id`

Project creation must require explicit workspace ID.

## Sync/quota

`GET /api/v1/sync-quota`
Returns daily/weekly used/limit, reset instants, eligibility.

`POST /api/v1/reports`
Creates synced report shell and consumes/commits quota according to idempotency semantics. Input includes project/workspace/local report id, requested effort, agent metadata, and safe high-level scan metadata. Does not accept source.

`POST /api/v1/reports/:id/progress`
Device credential + report-scoped permission. Runtime schema rejects unknown/forbidden fields.

`POST /api/v1/reports/:id/finalize`
Final metadata + encrypted/object upload reference or upload completion token.

`POST /api/v1/reports/:id/upload-intent`
Returns short-lived scoped upload mechanism after authorization. Do not make object storage ACL the authorization source.

## Report/view

`GET /api/v1/reports/:id`
Normal authenticated owner/workspace access. Returns authorized projection.

`GET /api/v1/reports/:id/events`
SSE after browser-session authorization.

## Sharing

`POST /api/v1/reports/:id/shares`
`PATCH /api/v1/shares/:shareId`
`DELETE /api/v1/shares/:shareId` or revoke endpoint
`GET /s/:slug` web route backed by server projection
`GET /api/v1/shares/:slug/report`

Every share read resolves viewer principal server-side before loading/serializing content.

## Fix/report lifecycle

Fixing source is local and host-agent controlled. Cloud endpoints may record status/comments but must never remotely command a local device to edit code without a future explicit, authenticated, user-approved feature.

## Admin

`GET /api/v1/admin/metrics/funnel`
`GET /api/v1/admin/metrics/scans`
`GET /api/v1/admin/versions`
`POST /api/v1/admin/support-grants`
`DELETE /api/v1/admin/support-grants/:id`

Support grant creation requires reason and bounded expiry and writes audit events.

## Error model

```json
{
  "error": {
    "code": "SYNC_WEEKLY_LIMIT_REACHED",
    "message": "Weekly cloud report limit reached.",
    "requestId": "...",
    "details": {"resetsAt": "..."}
  }
}
```

CLI messaging may be friendlier but should branch on stable error codes.
