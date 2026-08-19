# Product requirements document

## Product

Working name: Myrqen.

## Problem

Developers increasingly build software inside AI coding agents, but serious security testing still asks them to switch tools, understand pentesting infrastructure, buy separate model/API access, or interpret noisy static findings. The highest-friction users are solo developers and vibe coders: they benefit from security guidance but will abandon a product that feels like a security lab.

## Product thesis

The best insertion point is the coding agent the developer already trusts and pays for. Myrqen should install a structured pentester role into that environment. The host agent supplies reasoning; Myrqen supplies methodology, safety policy, local state, structured findings, reporting, cloud collaboration, and measurable quality.

## Primary promise

Run a strong authorized security assessment with one simple command and receive useful validated findings plus fixes without supplying another LLM API key.

## User priority

1. Solo developers and vibe coders.
2. Small teams/startups.
3. Agencies/security teams.
4. Enterprise later.

## Jobs to be done

- "Tell me whether the app I am building has real security problems before I ship it."
- "Show proof and context, not a wall of generic warnings."
- "Give my coding agent a precise fix task and verify the repair."
- "Let me share a professional report without exposing parts the recipient should not see."
- "Let my team keep project security history without uploading the whole repository."

## P0 features

### Agent/CLI
- Portable Agent Skill.
- Claude Code, Codex/OpenAI local workflows, and OpenCode launch support.
- `/myrqen <effort>` when available and `myrqen <effort>` everywhere.
- `low`, `high`, `xhigh`, `ultra`, `auto`.
- Login/link, workspace, reports, sync, doctor, update commands.

### Assessment
- Repository/framework/service discovery.
- Static/source-aware analysis.
- Configuration/secrets/dependency review.
- Controlled local dynamic web/API testing.
- Multiple test identities for access-control tests.
- Explicit exact authorization for external targets that are part of the project.
- Validation, dedupe, severity, confidence, evidence, remediation, and retest.
- No destructive behavior by default.

### Local report
- HTML, Markdown, JSON, SARIF; PDF when robust.
- Branded and offline-capable.
- Copy prompt to fix.
- Local copy remains even when cloud report expires.

### Account/cloud
- Email/password account creation; no outbound email POC.
- Browser-assisted device link.
- Personal workspace plus team memberships.
- Per-project workspace binding.
- Optional sync choice before each scan.
- Instant report URL + live privacy-safe progress when sync enabled.
- Free quota 5 reports/day and 15/week.
- Free cloud retention 21 days.

### Sharing
- One link can render different server-side projections for different accounts.
- Private/account-only, workspace, email/account allowlist, unlisted, optional anonymous, password, expiry, revoke, anonymize/redact.
- Branded exports use the viewer projection.

### Admin/product intelligence
- Signup/link/onboarding/scan/sync/report/share funnels.
- Agent, model, effort, token provenance, duration, version, OS.
- No product-analytics capture of report prose, source, secrets, raw HTTP, or vulnerability evidence.
- Break-glass report access only.

## Explicit non-goals for POC

- Native mobile reverse engineering.
- Wi-Fi/network infrastructure pentesting.
- Active Directory.
- Kubernetes/cloud-account takeover testing.
- Social engineering/phishing.
- General public-domain attack surface scanning.
- Autonomous destructive exploitation.
- Myrqen-hosted LLM inference.
- Email delivery, GitHub OAuth, Google OAuth.
- Pricing optimization before the product works.

## Definition of success

A new user completes install -> account/link -> project bind -> scan -> validated findings -> local report -> fix/retest -> optional synced report -> restricted share -> correct second-account projection without founder/admin intervention.

Product quality also requires benchmarked security performance, low false-positive/duplicate rates, zero unauthorized target expansion, and zero secret leakage through cloud progress/product analytics.
