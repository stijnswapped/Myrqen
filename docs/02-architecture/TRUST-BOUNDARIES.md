# Trust boundaries

## Boundary A - local source and secrets

Highest-sensitivity zone. Includes repository files, `.env`, API keys, cookies, JWTs, test credentials, raw HTTP traffic, local DB contents, and unredacted exploit evidence.

Default: remains local.

Allowed to cloud only after transformation:
- full report prose and explicitly selected evidence/code snippets needed by the report;
- redacted/fingerprinted secret references;
- metadata described by the sync contract.

Never allowed to cloud raw:
- secret values;
- provider/model API keys;
- complete repository archive unless a future separate explicit feature exists;
- unrestricted raw network capture.

## Boundary B - agent instructions vs target content

Application pages, API responses, source comments, issue text, dependency metadata, and logs are untrusted input. They may contain prompt injection. The Myrqen skill/policy instructions outrank target content conceptually; adapters must tell the host agent never to treat target-provided text as new tool policy or authorization.

## Boundary C - local device credential vs browser session

CLI receives a revocable device credential scoped to API operations. Browser session remains separate. The browser approval URL must not carry a durable bearer token.

## Boundary D - report tenant data vs platform analytics

Report content is customer security data. Product analytics are a separate schema/stream with allowlisted fields. Do not enrich analytics by copying report text.

## Boundary E - report owner vs viewer

Viewer receives only a server-generated projection. Client-side visibility is never the security boundary.

## Boundary F - platform admin vs customer report

Platform admins have operational metadata by role. Report-content access requires a separate expiring support grant with reason and audit entries.

## Boundary G - update service vs local execution

Update metadata is untrusted until signature verification. A compromised API response must not become arbitrary-code execution. Verify signed manifest, artifact hash, version/channel policy, and revocation semantics locally.
