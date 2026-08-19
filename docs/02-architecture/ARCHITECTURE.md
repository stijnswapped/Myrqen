# Architecture

## Design goals

- Local-first security execution.
- Host-agent-native reasoning, not Myrqen LLM inference.
- Consistent structured protocol across agent vendors.
- Strong separation between scan secrets and cloud product data.
- Useful entirely local report even when sync is off/unavailable.
- Easy evolution from POC to multi-tenant paid SaaS.

## Logical components

### 1. Host agent
Claude Code, Codex/OpenAI local agent, OpenCode, or another compatible coding agent. It owns model inference and normal coding-agent tools. Myrqen does not receive the provider API key.

### 2. Agent Skill
Portable instructions describing assessment phases, policy, report contract, and how to call the Myrqen CLI. Thin vendor adapters expose convenient invocation where possible.

### 3. Local CLI/control plane
Cross-platform executable/package that owns:
- account/device auth;
- secure local config;
- project/workspace binding;
- scan session lifecycle;
- authorization gates;
- structured finding validation/dedupe;
- redaction/fingerprinting;
- progress emission when sync opted in;
- local report/export generation;
- manual later sync;
- update checks and agent adapter installation.

### 4. Local project/runtime
Source tree plus local services. This is the primary scan trust zone. Docker/isolated runtimes may be used when available, but should not be required for ordinary useful scans.

### 5. Web/API
Multi-tenant control plane for accounts, devices, workspaces, projects, reports, shares, quotas, live progress, usage, and admin. Keep domain logic in packages so API can split from Next.js later.

### 6. PostgreSQL
Authoritative relational metadata: tenants, roles, report metadata, ACLs, quotas, analytics events, audit log, device credentials metadata, support grants.

### 7. Object storage
Encrypted EU-region report blobs/evidence/exports. Access only through authorized server routes/presigned mechanisms that honor report projection. Never expose bucket paths as authorization.

### 8. Realtime fanout
CLI sends authenticated progress to API. API publishes privacy-safe event to report stream. Browser subscribes using normal app session. Implement SSE first; use Valkey/Redis or replaceable broker across instances.

### 9. Worker
Retention deletion, quota cleanup/reconciliation, analytics aggregation, export jobs, stale device-link cleanup, and operational repair tasks.

## Monorepo target

```text
apps/
  cli/
  web/
  worker/
packages/
  analytics/
  brand/
  contracts/
  db/
  policy/
  report/
  skill/
schemas/
docs/
```

## Data flow - local-only scan

User -> host agent/skill -> CLI -> local source/runtime -> findings -> CLI validation/redaction -> local report files.

No live scan events, source, findings, or report contents are transmitted to cloud. Account/version/quota check operations may still occur only when required by product login/operation and must be documented separately from report sync.

## Data flow - synced scan

1. CLI checks quota and asks "Sync this scan?".
2. User says yes.
3. API atomically creates report shell and returns `report_id`, authenticated live URL, and upload/session capability scoped to that report.
4. CLI emits privacy-safe phase events.
5. Full scan still executes locally.
6. Local final report is validated/redacted.
7. Allowed full report/evidence is uploaded encrypted; full repository is never uploaded.
8. Browser transitions from live progress to complete report.

## Scale strategy

Start boring: one web service, one worker, Postgres, EU object storage, optional Valkey. Introduce separate API/ingestion/warehouse only after metrics show the need. Interfaces around event fanout, object storage, entitlements, and auth should be explicit to enable later replacement.
