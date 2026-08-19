# Application security assessment methodology

This methodology is for authorized project-local web/API assessment. It intentionally combines source reasoning and controlled runtime validation.

## Phase 0 - preflight and authorization

- identify repository root and technology stack;
- load Myrqen binding/policy;
- detect test/dev runtime without mutating production configuration;
- inventory explicit local origins and external origins referenced by project config;
- gate every external origin before dynamic interaction;
- identify available test identities and safe fixtures;
- detect whether isolation tooling is available without alarming the user.

## Phase 1 - application map

Build a concise threat-oriented map:
- entry points/routes/endpoints;
- auth/session implementation;
- roles/authorization checks;
- data stores and trust boundaries;
- file upload/download surfaces;
- server-side outbound requests/webhooks;
- parsing/deserialization/template/query construction;
- secret/config handling;
- admin/internal endpoints;
- third-party integrations;
- dependency/package manifests.

## Phase 2 - source/config/dependency review

Look for plausible root causes rather than matching only keywords:
- hard-coded or accidentally exposed secrets;
- insecure configuration/defaults;
- missing authorization at server-side boundaries;
- unsafe query/command/template/path composition;
- insecure file handling;
- unsafe server-side fetch/URL validation;
- token/session mistakes;
- trust of client-controlled role/ownership identifiers;
- dependency advisories appropriate to versions/usage, with uncertainty recorded;
- debug/admin exposure;
- security-sensitive business-logic assumptions.

## Phase 3 - controlled dynamic validation

Prefer local running services. Exercise routes with representative safe inputs and configured test identities. Seek to confirm whether a candidate issue is actually reachable and security-relevant.

Dynamic tests must stay within authorization/safety rules. Do not perform denial-of-service, destructive data changes, persistence, spam, uncontrolled account creation, third-party side effects, or scope expansion.

## Phase 4 - access-control matrix

When identities are available, compare:
- unauthenticated;
- normal user A;
- normal user B if needed for object-ownership boundaries;
- admin/test privileged user.

Focus on server-side enforcement and object ownership. Use non-destructive fixture objects. Record when a class cannot be tested because a required test identity/fixture is unavailable.

## Phase 5 - validation and dedupe

A candidate becomes:
- Verified: deterministic local/authorized evidence demonstrates the issue.
- Strong evidence: root cause and reachable path are strongly supported but full exploit proof is unavailable/unsafe.
- Needs review: plausible issue with insufficient validation.

Do not inflate severity because a category sounds serious. Severity reflects realistic impact in the assessed context.

## Phase 6 - remediation

For each actionable finding:
- name root cause;
- propose smallest durable fix;
- mention framework-native safeguards;
- include tests/regression checks;
- avoid broad rewrites unless necessary.

## Phase 7 - apply and verify

Only after user action:
- host agent changes source;
- run targeted tests;
- rerun the relevant security check;
- mark finding fixed only if verification actually passes;
- preserve original evidence and remediation history in local report revision.

## Coverage honesty

Every report lists what was not assessed or could not be validated. `ultra` is deeper, not omniscient. Never claim a system is secure solely because no findings were produced.
