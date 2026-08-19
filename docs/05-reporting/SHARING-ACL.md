# Sharing and report projections

## Core invariant

One share URL can serve different authorized views to different principals. Authorization and projection happen on the server before serialization. Hidden content is never sent to the client.

## Supported share modes

- private/owner only;
- authenticated account allowlist;
- workspace-only;
- unlisted link;
- anyone-with-link (explicit opt-in only);
- optional password;
- optional expiry;
- revocation;
- anonymized/redacted view;
- principal-specific section/finding visibility.

Modes can be composed only when semantics remain understandable. UI should show an exact preview of "who can see what".

## Principal resolution

At request:
1. resolve share token/slug to active share without leaking report existence on failure;
2. verify expiry/revocation/password gate as configured;
3. resolve browser identity if signed in;
4. derive principal set: user ID, normalized account email, workspace memberships, anonymous where explicitly allowed;
5. load matching projection policy;
6. apply deny-by-default projection to canonical report;
7. serialize only projected object;
8. audit access with safe metadata.

## Example

Same URL is manually sent to alice@example.com and bob@example.com.

- Alice rule: summary + findings F1/F2 + remediation, hide source evidence.
- Bob rule: summary + F2/F3 + evidence + remediation.
- Unlisted third logged-in account: denied.

The server returns structurally different JSON/HTML. Alice's payload never contains F3; Bob's never contains F1.

## Projection granularity

P0 support:
- named report sections;
- finding allow/deny IDs;
- per-finding field masks for evidence, code, reproduction, remediation, metadata;
- global anonymize/redact profile.

Do not begin with an arbitrarily programmable policy language. Use typed rules that are testable.

## Downloads

Every download endpoint resolves the same projection first, then renders. Never generate a full PDF and rely on a hidden front-end link to protect it.

## Cache safety

Private responses must not be cached under keys that omit viewer/projection identity. Prefer `private, no-store` initially for shared report content until safe cache partitioning is proven.
