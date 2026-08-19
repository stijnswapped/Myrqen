# Myrqen threat model

## Assets
- developer source code;
- local secrets and test credentials;
- security findings/evidence;
- device credentials;
- account/password/recovery material;
- workspace/report ACLs;
- update signing keys;
- admin/support privileges;
- audit logs;
- product analytics integrity.

## Adversaries / failure sources
- malicious content in the assessed application attempting prompt injection;
- compromised dependency/tool executed during testing;
- local malware or another user on shared machine;
- stolen device token;
- malicious/compromised share recipient;
- tenant attempting cross-workspace access;
- platform insider abusing admin access;
- compromised update/distribution infrastructure;
- accidental developer logging of secrets;
- agent hallucination causing unsafe target/action selection.

## Highest-risk scenarios and mitigations

### Target prompt injection causes exfiltration
Mitigate with explicit untrusted-content rule, CLI-enforced outbound/sync schemas, secret redaction, no arbitrary progress payload fields, approval gates, and test fixtures containing malicious instructions.

Implemented additionally: discovery records which files contain instruction-like passages, and an external origin that appears *only* in such a file is quarantined. The authorization gate refuses it outright, including when `--grant` is passed, because a human confirming a target that injected content authored is not meaningful consent. The refusal is disclosed in the report limitations. Covered by `apps/cli/test/discovery.test.mjs` and the acceptance journey.

### Cross-tenant/share data leak
Mitigate with tenant-scoped queries, server projections, authorization before object fetch/deserialize, no shared caches keyed only by report ID, export projection tests, and deny-by-default rules.

### Device-link theft/replay
High-entropy one-time request/verifier, short expiration, authenticated browser approval, one-time exchange, token hashing, revocation, audit.

### Update supply-chain compromise
Offline signature verification, pinned public root key, artifact digest, replay/downgrade rules, transparent version info, emergency revoke, reproducible/reviewable release pipeline later.

### Admin snooping
Separate operational role from report-content grant; require reason/expiry; immutable audit; possibly user-visible workspace audit later.

### Secret leakage to analytics
Compile-time/runtime typed event payloads, explicit allowlist, redaction middleware, tests using canary secrets, no generic `properties:any` ingestion path.

### False security confidence
Verification states, explicit coverage/limitations, benchmark harness, false-positive metrics, no "secure" certification wording from a no-finding result.
