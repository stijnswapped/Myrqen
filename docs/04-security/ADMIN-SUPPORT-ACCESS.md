# Platform admin and support access

## Normal platform-admin view

Allowed without report-content grant:
- user/workspace IDs and account status;
- funnel state;
- quota/usage;
- scan/report lifecycle state;
- timestamps/durations;
- agent/model/effort/token provenance;
- aggregate severity/category counts;
- client versions/OS;
- sanitized errors;
- share/access event metadata;
- abuse/version/update signals.

Not normally allowed:
- report prose;
- code snippets;
- evidence;
- raw finding descriptions;
- customer secrets/raw traffic.

## Break-glass support grant

To view report content, platform admin must:
1. choose exact resource scope;
2. enter a human-readable reason;
3. choose short expiry (default suggestion <= 60 minutes);
4. authenticate/re-authenticate according to admin policy;
5. receive a separate grant checked by report authorization middleware;
6. generate audit event on create/use/revoke/expire.

POC can be single-admin approval, but data model should permit two-person approval for enterprise operations later.

## Impersonation

Do not implement hidden user impersonation. If support-view-as-user becomes necessary, make it explicit, read-only by default, bannered, time-limited, and audited.
