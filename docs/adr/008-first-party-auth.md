# ADR 008: First-party email and password auth

Status: Accepted.

Context: the POC needs email/password accounts, no email delivery, non-email recovery, browser sessions kept separate from CLI device credentials, and no dependency that would drift during the build.

Decision: implement auth in `packages/auth` on Node's standard library. Passwords use scrypt with versioned parameters in the stored hash, sessions are opaque random tokens stored only as SHA-256 digests, and recovery codes replace the reset link that cannot exist without email. `MASTER-BUILD-PROMPT.md` permits "Better Auth or an equivalently simple first-party-friendly auth layer"; this is that layer.

Consequence: no native build step and no framework upgrade risk, at the cost of owning the implementation. Every rule lives once in `apps/web/lib/auth-service.ts`, which both the browser server actions and the JSON API call, so the two paths cannot diverge. Social login and SSO remain future work behind the same service boundary.
