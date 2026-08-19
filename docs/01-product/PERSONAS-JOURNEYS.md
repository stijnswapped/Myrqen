# Personas and journeys

## Persona A - solo builder / vibe coder

Security knowledge: low to medium. Patience for setup: very low. Uses Claude Code, Codex, OpenCode, Cursor-like tools, or another coding agent. Wants a trustworthy answer and an obvious fix path.

Experience rule: never turn optional infrastructure into a prerequisite lecture. Prefer "Myrqen can run a deeper isolated check when an isolated runtime is available" over repeated "Docker missing" alarms.

Core journey:
1. See simple website explaining local-first security testing.
2. Create account with email/password.
3. Copy one install/link command.
4. Browser confirms device.
5. Run `/myrqen auto` or `myrqen auto`.
6. Choose Personal workspace and optional sync.
7. See phases in plain language.
8. Open report and copy/apply a fix.
9. Re-run verification.

## Persona B - small team developer

Needs project continuity, shared reports, clear ownership, team-bound repository behavior, and low setup across machines.

Core journey:
1. Join team workspace through out-of-band process/manual setup in POC.
2. Clone repo containing safe `.myrqen/project.json` team binding.
3. Run scan without accidentally sending it to Personal.
4. Share report with teammate/customer using least-privilege projection.

## Persona C - workspace admin/security lead

Needs visibility and policy without platform-wide access.

Capabilities:
- manage members/roles when membership UI exists;
- manage workspace projects;
- review workspace reports according to ACL;
- configure share/retention/policy entitlements later;
- view workspace audit events.

## Persona D - platform admin/site owner

Needs product operations, funnel, model/effort/token/duration data, reliability, abuse controls, version adoption, and support diagnostics.

Must not become a default super-reader of customer security reports. Report-content access uses a break-glass workflow.

## Funnel milestones

Track each as an event plus derived conversion stage:

1. landing_viewed
2. signup_started
3. account_created
4. install_command_copied
5. device_link_started
6. device_link_approved
7. onboarding_completed
8. first_project_bound
9. first_scan_started
10. first_scan_completed
11. first_finding_validated
12. first_local_report_opened
13. first_sync_created
14. first_cloud_report_opened
15. first_fix_prompt_copied
16. first_fix_verified
17. first_share_created
18. first_share_opened_by_other_account

Admin dashboard must show dropoff counts/rates, median time between stages, and segmentation by client version/OS/agent/model/effort where privacy and sample size permit.
