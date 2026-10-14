# Security policy

Myrqen is a security tool. A defect in it is not an ordinary bug: a scanner that
misses a vulnerability, leaks a secret it was supposed to redact, or exceeds the
scope it was authorized for causes exactly the harm it exists to prevent. Reports
of any of those are welcome and taken seriously.

## Reporting a vulnerability

**Email `security@myrqen.cc`.** Please do not open a public issue for anything
that could be exploited before it is fixed.

Include whatever you have. What helps most:

- what you did, in enough detail to reproduce it
- the version — `myrqen --version` — and your platform and Node version
- the impact you believe it has
- whether you have told anybody else

If you would rather not use email, open a
[GitHub security advisory](https://github.com/stijnswapped/Myrqen/security/advisories/new)
on the repository. That is private until it is published.

### What to expect

This is a one-person project, and the response times below are what one person
can honestly commit to rather than what a company brochure would say.

| | |
|---|---|
| Acknowledgement | within 3 working days |
| Initial assessment | within 10 working days |
| Fix or a dated plan | depends entirely on severity, and you will be told which |
| Credit | offered by default, declined on request |

There is **no bug bounty**. There is no legal threat either: if you act in good
faith, stay within the scope below, and give us a chance to fix things before
going public, no action will be taken against you.

### In scope

- The `myrqen` CLI, and anything in the published npm package.
- The static analysis engine in `packages/scan`.
- The safety, authorization, and redaction policy in `packages/policy`.
- The report renderers in `packages/report` — including HTML injection through
  attacker-controlled finding content, which is a real class here because a
  report renders text an attacker wrote.
- The Agent Skill payload in `packages/skill`.
- The hosted service at `myrqen.cc`, `api.myrqen.cc`, and `docs.myrqen.cc`,
  **against an account you created yourself**.

### Out of scope

- Anything requiring physical access to a machine, or a compromised host.
- Denial of service against the hosted service by volume. Report the absence of a
  rate limit; do not demonstrate it.
- Social engineering, or anything involving another user's account or data.
- Missing hardening that is not exploitable. Reports are read, and they are not
  treated as vulnerabilities.
- Findings from an automated scanner, pasted without a working reproduction.

### Please do not

- Test against an account, workspace, share, or report that is not yours.
- Run destructive or bulk-automated traffic against the hosted service.
- Exfiltrate data. If you reach data that is not yours, stop, and say so in the
  report — that itself is the finding.

## Reporting a detection defect

A missed vulnerability or a false positive is not a security vulnerability in
Myrqen, but it is the thing this product is judged on, and it is the most useful
kind of report we can receive. **Open a public issue** using the
_Detection defect_ template.

The measured position is published rather than hidden: recall is **0.250** on a
corpus nobody had tuned against, on both readings of where a finding must land — within
eight lines of the line a case's author named, or anywhere in the range they marked.
It is **0.875** where the dangerous value reaches a language or runtime primitive and
**0.042** where it reaches a framework's own database or identity call, so a defect
whose sink is JavaScript is found far more reliably than one whose sink is your
framework's vocabulary. On the deliberately-correct half of that corpus, 4 of 32 files
drew a finding — **0.125**, or **0.063** counting only the ones stated as a claim rather
than a question, against a gate of 0.03. All four gates failed. Every one of those is the static pass alone, scored one
file at a time with no agent involved, against a gate of 0.90. The methodology is at
<https://myrqen.cc/benchmarks>. A missed case is expected, and a
reproducible one becomes a corpus case.

## Supported versions

| Version | Supported |
|---|---|
| `0.2.x` | yes |
| `0.1.x` | no — deprecated on npm, superseded by `0.2.0` |

There is one supported line because there has only ever been one release worth
supporting. Fixes go to the current version; there is no backport branch.

## What this project does not claim

- No third party has audited Myrqen.
- No certification, attestation, or compliance framework applies to it.
- The report encryption key is a deployment secret rather than a KMS-held key.
  This is a known limitation and is stated at <https://myrqen.cc/security>.
- Myrqen is a working codename that has passed a preliminary name-collision
  screen only, and the licence is source-available rather than open source.
