# POC acceptance tests

## A. Account and device
- New email/password account can be created with zero outbound email.
- Recovery material flow works.
- Link request expires and cannot be replayed.
- Browser approval required; visiting URL alone is insufficient.
- Device credential can be revoked and is rejected afterward.
- Durable credential never appears in URL/log output.

## B. Workspace binding
- Unbound repo prompts/selects workspace.
- Personal binding stays local and is Git-excluded.
- Team binding safe file can be committed without credentials.
- Team-bound clone does not silently fall back to Personal.
- Personal repo does not silently upload to Team.
- Explicit workspace switch/detach works.

## C. Scan/safety
- `myrqen low|high|xhigh|ultra|auto` starts a valid session.
- Portable skill can run through each target host in supported environment.
- Loopback service works without external authorization prompt.
- Discovered external origin triggers exact target confirmation.
- Approval of one origin cannot expand to siblings/subdomains.
- Cross-origin redirects are gated.
- Destructive-action policy blocks dangerous planned actions.
- Prompt-injection fixture cannot change scope or exfiltrate canary secret.
- No isolation runtime still yields useful safe coverage and calm UX.

## D. Findings/reports
- Invalid finding schema rejected with actionable local error.
- Duplicate evidence consolidates correctly.
- Severity and verification are independent.
- Local HTML works offline and makes no network request.
- Copy prompt to fix works and contains no canary secret.
- JSON/Markdown/SARIF exports validate.
- Apply fix requires explicit action.
- Apply & verify does not mark fixed until targeted check passes.

## E. Sync/quota
- If eligible, sync question appears exactly once before scan.
- Yes returns live URL immediately.
- No produces no progress traffic.
- Quota blocked produces no sync prompt/live progress.
- 5/day boundary at 06:00 UTC is correct.
- 15/week boundary Monday 06:00 UTC is correct.
- whichever cap is hit first blocks.
- idempotent retry does not double charge.
- failed reservation is released/reconciled.
- `myrqen sync <id>` later rechecks quota and never auto-runs.

## F. Retention
- free report expires exactly 21 days after successful sync per server time.
- expired share fails without content leak.
- object/evidence/derived exports are deleted.
- local copy remains.

## G. Sharing
- same URL yields different projections for Account A and Account B.
- hidden finding absent from JSON, HTML, SSR state, network payload, and export.
- unauthorized account receives no report metadata.
- password, expiry, revoke, workspace, unlisted, and anonymous explicit modes work.
- projection preview matches actual viewer response.

## H. Admin/analytics
- funnel stages populate from real events.
- agent/model/effort/duration segmentation works.
- exact and estimated token metrics are distinct.
- analytics reject arbitrary/report-content fields.
- platform admin metadata view has no report body.
- break-glass grant requires reason/expiry and logs every use.

## I. Updates
- valid signed manifest accepted.
- invalid signature, changed artifact hash, replay/downgrade, revoked version blocked.
- version pin behavior explicit.
- offline command still runs current safe version when permitted.

## J. End-to-end definition

Fresh machine/account -> install/link -> bind -> `/myrqen auto` or CLI fallback -> optional live URL -> validated benchmark finding -> local report -> copy/apply/retest -> cloud complete -> restricted share -> second account receives correct projection -> admin funnel shows privacy-safe events.
