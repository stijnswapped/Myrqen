<div align="center">

# Myrqen

### Security testing that runs inside the coding agent you already use.

**Static analysis finds the candidates. Your coding agent proves or disproves them against the application running on your machine.**

<br />

<a href="https://myqren.cc/">
  <img src="https://img.shields.io/badge/Website-myqren.cc-111827?style=for-the-badge" alt="Myrqen Website">
</a>
<a href="#quick-start">
  <img src="https://img.shields.io/badge/Quick_Start-Run_a_scan-2563eb?style=for-the-badge" alt="Quick Start">
</a>
<a href="LICENSE">
  <img src="https://img.shields.io/badge/License-Source--Available-7c3aed?style=for-the-badge" alt="Source Available">
</a>

<br />
<br />

**No repository upload. No separate model API key. No invented certainty.**

</div>

---

> [!IMPORTANT]
> **Myrqen is source-available, not open source.**
>
> The source is published because software that inspects your code should itself be inspectable. Copyright is retained and redistribution is not granted. See [LICENSE](LICENSE) for the plain-language terms and full legal text.

## Why Myrqen?

Most security scanners have to choose between reading your code and exercising your application.

Myrqen deliberately does both — but gives each job to the part of the system that can actually measure it.

|                            | Myrqen                                                 |
| -------------------------- | ------------------------------------------------------ |
| **Static analysis**        | Myrqen's own deterministic engine                      |
| **Dynamic verification**   | The coding agent you already use                       |
| **Application target**     | Your locally running application                       |
| **Repository upload**      | Not required                                           |
| **Separate model API key** | Not required                                           |
| **Finding states**         | Evidence-backed, refuted, or explicitly `needs_review` |
| **Reports**                | HTML, Markdown, JSON, and SARIF                        |
| **Hosted sync**            | Optional                                               |

The result is a scanner that distinguishes between **"this looks vulnerable"** and **"we observed this behaving vulnerably."**

---

## Quick start

Install the Agent Skill once:

```bash
npx myrqen link
```

Then, from any project:

```bash
myrqen auto
```

Want the entire scan to remain local?

```bash
myrqen auto --sync no
```

`--sync no` prevents report synchronization with the hosted dashboard. Without it, Myrqen asks whether the report should be synced and remembers that choice for that scan only.

> [!NOTE]
> Myrqen uses the coding agent you are already running. There is no separate model API key to configure or pay for.

---

## How it works

A Myrqen scan has two halves.

### 1. Myrqen finds candidates

The static pass belongs to Myrqen itself.

It parses TypeScript and JavaScript and follows attacker-controlled data through a function, including patterns that show up in real applications:

* destructured request reads;
* aliases and type assertions;
* values accumulated into arrays and later joined;
* data flowing into security-sensitive sinks.

When tainted input reaches a sink without an intervening protection, Myrqen records a **candidate**.

That pass runs whether or not an agent is involved, which means its behavior can be benchmarked and regression-tested independently.

### 2. Your agent settles the claim

Static analysis cannot observe a real HTTP response, browser state, authorization boundary, or runtime side effect.

So a candidate is not automatically promoted to a vulnerability.

The agent exercises the application running on your machine and records what actually happened:

```text
Source code
    │
    ▼
┌──────────────────────┐
│  Myrqen static pass  │
└──────────┬───────────┘
           │
           ▼
      needs_review
           │
           ▼
┌──────────────────────┐
│  Coding agent tests  │
│  the local app       │
└───────┬────────┬─────┘
        │        │
   observed   not reproduced
        │        │
        ▼        ▼
     verify     refute
        │        │
        └───┬────┘
            ▼
          Report
```

`myrqen finding verify` attaches the evidence the agent observed and raises the finding to `verified`.

`myrqen finding refute` records that the agent could not reproduce the candidate. It stays in the record instead of silently disappearing, so the result can still be reviewed or disputed.

A candidate nobody exercises remains **`needs_review`**.

That state is intentional. The report should say what the scanner established — and what it did not.

---

## What Myrqen will not do

### It will not tell you that you are secure

Myrqen reports what it was able to establish and explicitly states what it could not reach.

A scanner finding nothing is not a clean bill of health.

### It will not test systems you have not authorized

Anything outside your own machine requires explicit, exact authorization.

A grant for:

```text
https://api.example.com
```

does **not** authorize:

```text
http://api.example.com
https://example.com
https://api.example.com:8443
```

Scheme, origin, and port boundaries matter.

### It will not perform destructive actions

Myrqen's policy refuses actions such as mass deletion, request flooding, credential spraying, persistence, exfiltration, and authorization-scope expansion.

A refusal is recorded rather than silently ignored.

### It will not treat repository text as instructions

Source code, READMEs, comments, fixtures, issue text, and other repository content are **data**.

If repository content attempts to instruct the scanner to ignore its policies, that attempt is recorded as an observation instead of followed.

### It will not print discovered secrets

Credentials are described by **location and type**, not by value.

Secret values are redacted before being stored anywhere, including locally.

---

## Reproducible benchmarks

Detection claims are only as useful as the corpus behind them.

Myrqen publishes both the corpus and the scorer.

| Vulnerable cases | Safe near-misses | Vulnerability classes | Architectures |
| ---------------: | ---------------: | --------------------: | ------------: |
|           **78** |           **78** |                **38** |        **10** |

Run the full fixture benchmark:

```bash
pnpm benchmark
```

Or score the vulnerability corpus directly:

```bash
pnpm benchmark:corpus
```

The corpus covers application shapes built with **Express, Fastify, Koa, Hono, `node:http`, Next.js route handlers, Next.js server actions, tRPC, GraphQL resolvers, and FastAPI**.

Every vulnerable case has a corresponding **safe near-miss**: code with the same suspicious surface that performs the same job correctly, differing only in the security decision that matters.

That distinction is important.

A scanner that flags both the vulnerable and correct form of a pattern does not merely have false positives — it trains developers to stop trusting its output.

### The corpus is designed to be difficult to game

* File, function, and variable names do not reveal the vulnerability being tested.
* Every case is scanned independently in a temporary directory.
* The engine sees a path it has not seen before.
* Matching is strict: **class, route, and line** must all be correct.
* A finding in the correct file but at the wrong location is still a miss.
* Cases written in languages the engine does not parse are reported separately and are never counted as recall failures.

Both benchmark commands report recall, precision, per-class results, and the safe-case false-positive rate.

They also exit non-zero when results fall below the release gates or regress against the committed baseline.

The latest passing baselines live in:

```text
benchmark/corpus-baseline.json
benchmark/baseline.json
```

Run the benchmarks rather than trusting a performance number copied into a README.

---

## Run from source

Development requires **Node.js 22 or newer** and **pnpm**.

```bash
pnpm install
pnpm build
node apps/cli/dist/myrqen.mjs --help
```

Run the built CLI against another project:

```bash
cd /path/to/your/project

node /path/to/myrqen/apps/cli/dist/myrqen.mjs auto --sync no
```

---

## Repository structure

| Path                                       | Purpose                                                                               |
| ------------------------------------------ | ------------------------------------------------------------------------------------- |
| [`apps/cli`](apps/cli)                     | The `myrqen` command                                                                  |
| [`packages/scan`](packages/scan)           | Static analysis and intra-procedural taint tracking over the TypeScript AST           |
| [`packages/policy`](packages/policy)       | Authorization scope, prohibited actions, redaction, deduplication, and finding intake |
| [`packages/report`](packages/report)       | HTML, Markdown, JSON, and SARIF report rendering                                      |
| [`packages/skill`](packages/skill)         | The portable Agent Skill and its reference documents                                  |
| [`packages/contracts`](packages/contracts) | Shared schemas and types                                                              |
| [`packages/auth`](packages/auth)           | Password hashing, recovery codes, session tokens, and device tokens                   |
| [`benchmark`](benchmark)                   | Case corpus, scorer, and fixture harness                                              |
| [`fixtures`](fixtures)                     | Deliberately vulnerable and deliberately correct test applications                    |

---

## The Agent Skill

The portable source of truth lives in:

```text
packages/skill/myrqen
```

It contains the `SKILL.md` plus reference documents describing Myrqen's methodology, safety boundaries, finding contract, and CLI.

```bash
npx myrqen link
```

installs the skill for **Claude Code, Codex, and OpenCode**, and writes it to `~/.agents/skills` for other agents that follow the same convention.

It is plain Markdown.

You can — and should — read the instructions your agent will follow before allowing it to run them.

---

## What's published

The hosted Myrqen dashboard is a separate application and is **not** included in this repository.

This source repository is generated from the working monorepo by a publication script with release gates that refuse to publish when:

* an included package depends on an unpublished package;
* a file outside test or fixture paths contains a credential-shaped literal;
* an included file imports from a path that has been excluded.

The goal is for the published source to remain inspectable without accidentally exposing private application code or credentials.

---

## A note on the fixtures

[`fixtures/vuln-shop`](fixtures/vuln-shop) is **deliberately vulnerable**.

It exists exclusively as a test target, binds to localhost, and must never be deployed.

Its committed credential is a canary used to test Myrqen's redaction behavior. The benchmark verifies that the credential never appears in generated report output.

> [!WARNING]
> Do not deploy or expose the vulnerable fixtures to an external network.

---

## Reporting a security issue

If you find a security issue in this repository, open an issue containing:

* what you found;
* the smallest useful reproduction;
* the minimum source excerpt needed to make the problem clear.

Please do **not** include a working exploit against infrastructure you do not own or have explicit authorization to test.

If the issue concerns Myrqen's hosted service rather than the published source, say so in the issue without publishing the sensitive details. The hosted application is not part of this repository, and a public issue is not the appropriate place for those details.

---

## Third-party components

Myrqen's production dependencies include:

* [`typescript`](https://www.npmjs.com/package/typescript) — Apache-2.0
* [`ajv`](https://www.npmjs.com/package/ajv) — MIT
* [`ajv-formats`](https://www.npmjs.com/package/ajv-formats) — MIT
* [`commander`](https://www.npmjs.com/package/commander) — MIT

Their transitive dependencies are licensed under MIT, Apache-2.0, or BSD-3-Clause terms.

Those licenses travel with their respective packages and are unaffected by Myrqen's repository license.

---

## Licence

Myrqen is distributed under the **Myrqen Source-Available Licence 1.0**.

You may read, study, and run the software against systems you are authorized to test, including for internal and commercial work.

You may **not** redistribute it, publish a fork, or offer it as a service.

It is not OSI approved and is not an open-source licence.

Read the complete terms in **[LICENSE](LICENSE)**.

---

<div align="center">

### Security claims should be inspectable.

[Website](https://myqren.cc/) · [Quick start](#quick-start) · [Benchmarks](#reproducible-benchmarks) · [Licence](LICENSE)

</div>
