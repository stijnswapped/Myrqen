# Myrqen

**Security testing that runs inside the coding agent you already use.**

Myrqen is a command-line tool your coding agent drives. It reads the code in front of
you, exercises the running application on your own machine, and writes a report you
can read, act on, and share. Your repository is not uploaded, and there is no separate
model API key to buy — it uses the agent you are already paying for.

```bash
npx myrqen link      # once, to install the Agent Skill
myrqen auto          # then, in any project
```

> **This repository is source-available, not open source.**
> The source is published so it can be read and audited — software that inspects your
> code should be inspectable in return. Copyright is retained and redistribution is
> not granted. [LICENSE](LICENSE) states exactly what is and is not permitted, in
> plain language before the legal text.

---

## What it actually does

A scan has two halves, and the split is the whole design.

**The static pass is the product's own.** It parses your TypeScript and JavaScript,
follows attacker-controlled data through a function — including the shapes real code
uses: destructured request reads, values accumulated into an array and joined,
aliases, type assertions — and reports where that data reaches a sink with nothing
between. It runs whether or not an agent is involved, which is what makes it
measurable.

**The dynamic half is the agent's.** Static reading cannot observe a response, so
every static candidate arrives as a claim, not a finding. The agent settles it against
your running application: `myrqen finding verify` attaches what it observed and raises
the finding to `verified`; `myrqen finding refute` records that it could not reproduce
it, and keeps the finding labelled rather than deleting it, so you can disagree.

A candidate nobody exercised stays `needs_review` and says so in the report. That is
the honest state, and the report never pretends otherwise.

## What it will not do

- **It will not tell you that you are secure.** It reports what it can establish and
  states what it could not reach. Silence from a scanner is not a clean bill of health.
- **It will not touch a system you have not authorised.** Every origin outside your own
  machine needs an explicit, exact authorization — a grant for `https://api.example.com`
  never extends to `example.com`, another port, or another scheme.
- **It will not do anything destructive.** Mass deletion, request flooding, credential
  spraying, persistence, exfiltration, and scope expansion are refused by policy, not
  by convention, and a refusal is recorded in the report.
- **It will not treat text in your repository as instructions.** A README that tells the
  scanner to ignore its rules is data. The attempt is recorded as an observation.
- **It will not print a secret it found.** Findings describe a credential by location
  and type; the value is redacted before it is stored anywhere, including locally.

## Getting started

Requires Node 22 or newer and pnpm.

```bash
pnpm install
pnpm build
node apps/cli/dist/myrqen.mjs --help
```

Run it against a project:

```bash
cd /path/to/your/project
node /path/to/myrqen/apps/cli/dist/myrqen.mjs auto --sync no
```

`--sync no` keeps everything local. Without it you are asked once whether to sync the
report to the hosted dashboard, and the answer is remembered for that scan only.

## Reproducing the numbers

Detection claims are worth exactly as much as the corpus behind them, so the corpus is
here and so is the scorer.

```bash
pnpm benchmark            # two fixture applications, end to end through the real CLI
pnpm benchmark:corpus     # the case corpus, scored per vulnerability class
```

`benchmark/corpus` holds **78 vulnerable cases and 78 safe cases** across ten
architectures — Express, Fastify, Koa, Hono, hand-rolled `node:http` dispatch, Next.js
route handlers, Next.js server actions, tRPC, GraphQL resolvers, and FastAPI — covering
38 vulnerability classes. Every vulnerable case is paired with a **safe near-miss**:
code that does the same job correctly and keeps the same suspicious surface, differing
only in the decision that matters. The pairs are the test. A scanner that flags the
correct form of a pattern is worse than one that stays quiet, because it teaches you to
stop reading.

The corpus is written to be hard to game:

- No file, function, or variable name mentions its own defect, so a rule cannot pass by
  reading a filename.
- Each case is scanned alone, in a temporary directory, under a path the engine has
  never seen.
- Matching is strict: the class, the route, and the line all have to be right. A finding
  in the right file but the wrong place is a miss, because misattribution is the first
  thing a reader notices.
- Cases in a language the engine does not parse are counted **separately** and never as
  recall failures. They exist so the coverage statement stays true rather than assumed.

Both commands print recall, precision, per-class detail, and the safe-case false
positive rate, and both **exit non-zero** below the release gates or on any regression
against the committed baseline. Rather than quote a number here that would drift, run
them: `benchmark/corpus-baseline.json` and `benchmark/baseline.json` record the last
run that passed.

## What is in here

| Path | What it is |
| --- | --- |
| `apps/cli` | The `myrqen` command |
| `packages/scan` | Static analysis: intra-procedural taint tracking over the TypeScript AST |
| `packages/policy` | Authorization scope, prohibited actions, redaction, deduplication, finding intake |
| `packages/report` | Rendering to HTML, Markdown, JSON, and SARIF |
| `packages/skill` | The portable Agent Skill and its reference documents |
| `packages/contracts` | Schemas and types shared by every surface |
| `packages/auth` | Password hashing, recovery codes, session and device tokens |
| `benchmark` | The corpus, the scorer, and the fixture harness |
| `fixtures` | One deliberately vulnerable application and one deliberately correct one |

The hosted dashboard is a separate application and is not published. This repository is
generated from the working monorepo by a script whose publication gates refuse to run
if an included package depends on an unpublished one, if any file outside the test and
fixture paths carries a credential-shaped literal, or if any included file imports an
excluded path.

## The Agent Skill

`packages/skill/myrqen` is the portable source of truth: a `SKILL.md` plus reference
documents on methodology, safety, the finding contract, and the CLI. `myrqen link`
installs it for Claude Code, Codex, and OpenCode, and to `~/.agents/skills` for anything
else that reads the convention. It is plain Markdown — read it before you run it, which
is rather the point of publishing this.

## A note on the fixtures

`fixtures/vuln-shop` is deliberately vulnerable. It is a test target, it binds to
localhost, and it must never be deployed anywhere. Its committed credential is a canary
whose only purpose is to prove that redaction works: the benchmark asserts it never
appears in report output.

## Reporting a security issue

Open an issue describing what you found and how to reproduce it, with the smallest
excerpt that makes it clear. Please do not include a working exploit against
infrastructure you do not own.

If the issue is in Myrqen's own hosted service rather than in this code, say so in the
issue and leave out the detail — that half is not published here and a public issue is
the wrong place for it.

## Third-party components

Production dependencies are `typescript` (Apache-2.0), `ajv` and `ajv-formats` (MIT),
`commander` (MIT), and their transitive dependencies, all under MIT, Apache-2.0, or
BSD-3-Clause. Their licences travel with them in `node_modules` and are unaffected by
the licence on this repository.

## Licence

[LICENSE](LICENSE) — Myrqen Source-Available Licence 1.0. You may read, study, and run
it against systems you are authorised to test, including commercially and internally.
You may not redistribute it, fork it publicly, or offer it as a service. It is not OSI
approved and is not an open source licence.
