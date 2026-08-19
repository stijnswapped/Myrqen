# Authentication and device linking

## POC account auth

Email + password. No outbound email. Do not require email verification. Do not show a "check your inbox" flow.

Because email delivery is absent, do not offer a fake email password-reset flow. Generate recovery codes at account creation or implement another explicit non-email recovery mechanism. Hash passwords with a current memory-hard/password hashing algorithm supported by the chosen auth stack.

## Device link goals

- user copies/runs one command;
- browser authenticates account;
- browser clearly approves device;
- open app tabs can reflect approval using authenticated realtime/polling;
- terminal continues automatically;
- durable CLI credential never appears in browser URL/logs.

## Protocol sketch

1. CLI generates local verifier and challenge/request.
2. `POST /device-links` creates short-lived request, e.g. 10 minutes.
3. Server returns opaque `public_request_id` + approval URL.
4. CLI opens browser and polls/exchanges using verifier proof.
5. Browser user signs up/logs in.
6. Approval page shows device name, OS, CLI version, and project-independent scope.
7. User approves.
8. Server marks request approved for user.
9. CLI performs one-time exchange and receives device token.
10. Store token in OS keychain; fallback to permission-restricted config only when keychain unavailable.
11. Server stores only token hash/key ID and device metadata needed for revocation/audit.

## Security

- high entropy, short expiry;
- one-time consume;
- CSRF/session protection on approval;
- no approval by merely visiting link;
- no durable token in URL;
- revoke per device;
- rotate safely;
- rate limit link creation/exchange;
- audit create/approve/exchange/revoke;
- do not trust CLI-supplied user ID.
