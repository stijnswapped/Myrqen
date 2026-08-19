# Agent integration strategy

## Core rule

One portable Myrqen Agent Skill is the behavioral source of truth. Vendor-specific files are thin adapters for discovery/invocation, not divergent security methodologies.

## Claude Code

Install project/global skill in currently documented compatible location. Where Claude exposes skills as slash invocations, support `/myrqen auto`. Keep fallback `myrqen auto` documented and functional.

## OpenAI/Codex

Use the current Agent Skills/local execution mechanism and universal CLI. Do not assume a slash-command implementation that is not present in current official docs.

## OpenCode

Publish skill in portable `.agents/skills/myrqen` and/or its documented compatibility locations. Verify actual current discovery precedence and avoid duplicate conflicting IDs.

## Installer

`myrqen link` or one web-provided `npx ...` bootstrap should:
1. detect OS/arch;
2. detect known agent installations conservatively;
3. install/update the portable skill in compatible global/project location chosen by user/installer policy;
4. never overwrite user custom files without backup/explicit safe rule;
5. create browser device-link request;
6. return to terminal after approval;
7. run `doctor` and print one primary next command.

## Model metadata

Adapters may discover agent/model/version using documented host metadata. If unavailable, store `unknown` rather than guessing. Do not access or upload provider credentials.

## Token accounting

Define:
- exact: host reports authoritative usage for relevant scan turns;
- estimated: Myrqen estimates from available transcript/usage proxies and labels the method/version;
- unavailable: cannot reasonably measure.

Admin averages must allow filtering to exact-only and must not visually merge estimated values as if exact.

## Portability invariant

Security methodology and report schema must work if all vendor-specific convenience is removed and the user can only invoke `myrqen auto` from a host agent with shell/code/browser capabilities.
