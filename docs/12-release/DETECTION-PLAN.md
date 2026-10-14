# Plan: make Myrqen's detection trustworthy

> **Superseded in part, 2026-08-23.** Every `0.324` below was current when this was
> written and is not now: two further fixes took `benchmark/holdout-3` to **0.441**,
> and the miss decomposition changed with it — attribution is **3** cases, not five,
> and route matching costs one case, not five. The figures were transcribed from
> here into the ceiling table published on `/benchmarks`, which therefore rendered
> `Today 0.324` beside a corpus table reading `0.441` for two releases. The
> generator no longer reads this file, and
> `scripts/generate-benchmark-summary.mjs` now refuses to publish a "Today" row
> that disagrees with the artifact. **For current figures use
> [`docs/internal/detection-baseline.md`](../internal/detection-baseline.md); for
> the current decomposition and the plan that replaces §"Ceiling" below, use
> [`docs/internal/detection-improvement-plan.md`](../internal/detection-improvement-plan.md).**
> The blind figure — **0.294**, the only quotable held-out result — is unchanged.

> **Status, 2026-08-21.** Priority 1 is done: `benchmark/holdout-3` was authored
> blind, scored once at **recall 0.294**, and recorded in `HOLDOUT-PROTOCOL.md`
> before anything changed. Priority 2 is done: the `perimeter-cors` false positive
> is closed, and precision is now **1.000** with a **0.000** safe-case
> false-positive rate on all four corpora. Holdout-3 is **burned** — it was spent
> on four fixes, three of them precision, one of them the Drizzle/Kysely query
> builder. Post-fix recall on it is 0.324.
>
> **The open question is unchanged and is now the only one: recall.** 0.324
> against an enforced 0.90 gate. `HOLDOUT-PROTOCOL.md` classifies all 23 cases —
> five attributed wrongly, six cross-module by design, two reachable through a
> local call, eight rule gaps in classes the engine does not model at all, and one
> disagreement about the name of a defect rather than whether it was found.
> Priority 1 below now means **Run 4**, authored blind after those fixes.

Written to be picked up cold, in a new session, by someone with no memory of the
work that produced it. Everything here is measured; where it is not, it says so.

Read `HANDOFF.md` first for the state of the whole repository.

---

## How to use this file

**This is an instruction, not only a briefing. Execute it — do not summarise it
back.** Work the priorities in Section 4 in order, verify with the commands
given, and report measured numbers rather than intentions.

### It takes two sessions, and they must not be the same session

This is the one thing that will quietly ruin the work if it is ignored.

**Priority 1 needs an author who has never read the scanner.** A corpus written
with the implementation in view tests the implementation's own idea of the
problem, which is worth nothing. **Priorities 2 onward need someone reading the
scanner constantly.** The same session cannot do both: the moment it opens
`packages/scan/` it has disqualified itself from writing the corpus, and the
moment it writes a rule after reading the corpus, the corpus is burned before it
was ever scored.

So:

| | Session A — the author | Session B — the engineer |
|---|---|---|
| Does | Priority 1 only: write `benchmark/holdout-3`, build its manifest, score it **once**, record the result | Priorities 2, 3, 4 |
| May read | `benchmark/corpus/README.md`, `benchmark/build-corpus-manifest.mjs`, `benchmark/score-corpus.mjs` (manifest shape only), `packages/contracts/src/domain.ts` (severity vocabulary), and `HOLDOUT-PROTOCOL.md` **down to the "Run 1" heading only** | everything |
| Must never read | `packages/scan/`, any existing corpus's case files, this file's Section 2 or Section 5, `DETECTION-BASELINE.md` | — |
| Must never run | any scanner or scorer while authoring — the scorer runs once, at the end | — |

If you are Session A: stop at the end of Priority 1, record the number in
`HOLDOUT-PROTOCOL.md` whatever it says, and hand back. Do not fix what you found.

**One session can do both if it delegates the authoring.** A fresh subagent whose
prompt carries the corpus specification and nothing about the implementation is
blind in the way that matters, and its ignorance is enforced by its context
rather than by its self-restraint. Give it the Session A column above as its
rules, one application family, and let it finish. You keep reading the scanner;
it never does. This is what `NEXT-SESSION-PROMPT.md` instructs.

If you are Session B: check that the corpus you are about to work against has a
recorded run in `HOLDOUT-PROTOCOL.md` and that no scanner change has been made
since. If it does not, **stop and say so** — there is no scoreboard, and any
number you produce afterwards is a development number wearing a holdout's clothes.
As of 2026-08-21 that is true of every corpus on disk: Run 4 has to be written
before another generalisation claim is possible.

### On parallelism

Fan out for **many independent files behind a fixed interface** — adapters are
exactly that, and thirteen were written this way successfully. Do **not** fan out
corpus authoring: two attempts spent roughly 1.2M subagent tokens and produced
one usable family, because a blind author must write a whole realistic
application before any of it is scorable and an interrupted one leaves nothing.
One or two agents at a time there, one family each, each allowed to finish.

### What this file does not cover

Detection is not the only thing left in the original brief. Two other items are
outstanding and are **not** in scope here:

* ~~The cloud report UI has never been rendered in a browser.~~ **Done
  2026-08-21.** `pnpm test:web-visual` (`tests/web-report-visual.mjs`) seeds a
  real scan through the real server and measures the live scan page, the finished
  report and a principal-scoped share page across seven viewport widths — 118
  checks. It found three defects, all fixed.
* **`myrqen@0.1.0` is already live on npm** — published 2026-08-20, from a tree
  that predates the packaging work. It ships no README and no LICENSE, declares
  no license or repository, and includes the sourcemap. The current tree fixes
  all of that, but `0.1.0` can never be reused, so the next release needs a new
  version and the live one probably wants deprecating. Run
  `pnpm publish:preflight` — it reports registry state and lists every step that
  needs a person. Publishing itself is still a separate, deliberate act and is
  not authorised here.

Everything else from the original brief is done and verified: the agent-integration
installer, packaging, the local HTML report, detection probe side-effects, and the
Windows/WSL platform fixtures.

---

## 1. Where detection actually stands

Run these. They take a few minutes and they are the only honest starting point.

```bash
cd /Users/stijn/thuis/myrqen
pnpm build
node benchmark/score-corpus.mjs                               # development corpus
node benchmark/score-corpus.mjs --corpus benchmark/holdout    # held-out 1
node benchmark/score-corpus.mjs --corpus benchmark/holdout-2  # held-out 2
node benchmark/explain.mjs --corpus benchmark/holdout-2        # why each case passed or failed
```

Expected, as of 2026-08-21:

| Corpus | Recall | Crit/high | Precision | Safe-FP | What it means |
|---|---|---|---|---|---|
| `benchmark/corpus` | 1.000 | 1.000 | 1.000 | 0.000 | The rules were written against it. Proves nothing. |
| `benchmark/holdout` | 1.000 | 1.000 | 1.000 | 0.000 | **Burned.** Tuned against, twice. |
| `benchmark/holdout-2` | 0.545 | 0.545 | 1.000 | 0.000 | **Burned deliberately.** Was 0.091, then 0.455. |
| `benchmark/holdout-3` | 0.324 | 0.324 | 1.000 | 0.000 | **Burned 2026-08-21.** Scored once clean at **0.294**. |

The only held-out number this project has ever produced honestly is **0.294**, on
holdout-3, before any change was made in response to it. Everything else in this
table is a development number.

**There is exactly one clean measurement of generalisation, and it is 0.294.**
That is the single most important fact in this document. It is the only detection
number anyone may quote outside the project, and it must be quoted with its date
and its corpus attached.

### Two sets of numbers are in circulation, and the stricter one has no source

**The only gate anything enforces** is in `benchmark/score-corpus.mjs`, and the
process exits non-zero below it:

```
criticalHighRecall 0.95   overallRecall 0.90   precision 0.90   safeFalsePositiveRate 0.03
```

Earlier versions of this document quoted **critical/high recall ≥ 0.97, overall
recall ≥ 0.93, precision ≥ 0.95, safe-decoy false positives ≤ 0.02** and
attributed them to `MASTER-BUILD-PROMPT.md`. **That attribution is wrong.**
`MASTER-BUILD-PROMPT.md` asks for a benchmark that *measures* recall and the
false-positive rate and names no number at all. The stricter set is an aspiration
somebody wrote down; it is not a requirement anybody set.

This matters more than a citation usually would, because Section 4's ceiling
arithmetic shows the choice of target decides whether cross-module data flow — the
largest piece of work in this document, and a capability the product deliberately
delegates to the host agent — has to be built at all. **Pick the number
deliberately before spending anything against it.**

### Read `docs/12-release/HOLDOUT-PROTOCOL.md` before touching a corpus

The rule that makes any of these numbers worth quoting: **if the scanner changes
after a corpus is scored, that corpus is burned.** Not "reused with a note".
Every run and every burn is recorded there, including why holdout-2 was spent.

---

## 2. What the two measured runs established

Both are structural, both are load-bearing for this plan, and neither is a guess.

### The engine is blind without an entry point

Every one of the 36 data-flow rules starts from a caller-controlled value. No
entry point means no such value, which means no rule can fire, which means a file
full of defects comes back clean. On holdout-2's first run, **ten of eleven
scored misses produced no candidate at all** for exactly this reason.

The fix is an adapter per architecture, in `packages/scan/src/ast/frameworks/`.
Thirteen exist. Each declares two things: the address (for the report) and which
bindings inside a handler hold caller data (`seeds`), because the generic
parameter-name model cannot infer either.

Measured effect of that loop, run twice on held-out 1: **0.148 → 0.296** from
adapters alone, then **0.296 → 1.000** once the rules learned the shapes the
adapters exposed. Adapters alone are about a third of the win. Do not stop there.

### Taint is intra-procedural, and that is a design decision

A defect reached by a cross-file call is invisible to the static pass. The
product gives cross-module reasoning to the host agent, not to the engine.
Several holdout-2 cases are unreachable for this reason and were correctly
classified as out of scope rather than forced.

**Do not widen taint to reach them.** An agent tried a version of that during
this work and it immediately produced a false positive in Myrqen's own source
(`apps/cli/src/integrations/detect.ts`, a validated executable path reported as
command injection). It was closed by requiring *observed* taint rather than
*inferred* taint across a second boundary. That guard is in
`packages/scan/src/rules/injection.ts` — do not remove it.

---

## 3. The loop that works

For each architecture, in this order. It has been run twice end to end.

1. **Write the adapter.** One new file in `packages/scan/src/ast/frameworks/`,
   exporting a `FrameworkAdapter`. Read `nitro.ts` for a file-routed example and
   `serverless.ts` for a call-shaped one. Register it in
   `frameworks/index.ts` — that is the only shared file an adapter touches.
2. **Verify the entry points fire** before touching any rule:
   ```bash
   node benchmark/explain.mjs --corpus <corpus> --case <id> --verbose
   ```
3. **Then the rules.** The adapter makes the data reachable; the rules still have
   to recognise the shape. This is where two thirds of the recall is.
4. **Prove you invented nothing.** Build one engine with the change and one
   without, scan `apps/`, `packages/`, `fixtures/` and `tools/` with both, and
   diff the candidate sets. Any finding the change *adds* to this repository's own
   source is a false positive until defended in writing. Every agent that did
   this caught something; the one that skipped it shipped a false positive.
5. **Re-measure the development corpus and held-out 1 after every change.** Both
   must stay at 1.000 / 1.000 / 0.000. A change that costs corpus precision is
   the wrong change — find the shape that separates the defect from the correct
   code instead of widening the net.

### Building a private engine

Agents working in parallel overwrite each other's `dist`. Always:

```bash
MY=/tmp/eng-$$
npx tsc -p packages/scan/tsconfig.json --outDir $MY --tsBuildInfoFile /tmp/tsb-$$.json
ln -s /Users/stijn/thuis/myrqen/node_modules $MY/node_modules
node benchmark/score-corpus.mjs --engine $MY/index.js
```

`tsc` shares a `tsbuildinfo` across output directories and will **silently skip
emitting** into a fresh one, so the `--tsBuildInfoFile` is not optional. Confirm
the engine you just built is not stale before believing a number.

---

## 4. The work, in priority order

### What recall can and cannot reach — read this before spending anything

The 34 vulnerable cases of holdout-3, classified in `HOLDOUT-PROTOCOL.md`, give a
ceiling for each category of work. Cumulative, on that corpus:

| After | Recall |
|---|---|
| today | 0.324 |
| + the 5 attribution cases | 0.471 |
| + the 8 rule gaps | 0.706 |
| + the 2 reachable through a local call | 0.765 |
| + the 6 cross-module cases | 0.941 |

> **Superseded 2026-08-23.** The baseline was 0.441 when this was written, is 0.500
> today, and the decomposition is 6 rule
> gaps, 2 local-call, 3 attribution, 6 cross-module — reaching 32 of 34. See
> [`detection-improvement-plan.md`](../internal/detection-improvement-plan.md).
> `withoutCrossModule` is still 0.765. Do not transcribe the table above; the
> published version is generated and asserted against the artifact.

**Everything except cross-module tops out at 0.765**, and on a corpus nobody has
seen yet it lands lower, because a new architecture brings new gaps. So the
enforced 0.90 gate is not reachable for the static pass without cross-module data
flow — which is a capability this product deliberately gives to the host agent
rather than to the engine.

**Decided 2026-08-21, before Run 4 exists** — see "The scope decision" at the end
of `HOLDOUT-PROTOCOL.md`. The gate numbers did not move. What moved is the
population they are computed over: a case may be marked `outOfScope:
"cross_module"` by its author and is then scored separately with its own recall
figure, exactly as a case in a language the engine cannot parse already is. The
alternative — lowering 0.90 to something the static pass can reach — would have
hidden a deliberate architectural boundary inside an arbitrary number and left
nobody able to say how large it is. `benchmark/holdout-3` is deliberately **not**
relabelled; the mechanism applies from Run 4 onward, to an author marking cases
while writing them.

`node scripts/detection-report.mjs` (`pnpm detection:report`) prints both halves
side by side with what each one cannot say, so neither gets quoted as the other.

The reasoning that led there, kept because the next person will reach this fork
again:

1. **Measure the two halves separately.** The scorer scans each case alone with no
   agent involved, so it measures the static pass, not the product. Gate the static
   pass at what it can reach and gate the *combination* at the number that matters
   to a user. This is the cheapest answer and arguably the most truthful one, but
   it needs a harness that can score the agent's contribution, which does not
   exist.
2. **Build cross-module flow.** A module graph and taint that crosses it. The
   largest item in this document, and the one most likely to manufacture false
   positives — `packages/scan/src/ast/route-index.ts` is the precedent worth
   copying, because it reads other modules for route attribution only, resolves
   imports to paths rather than matching names, and refuses to answer when a
   handler is registered twice.
3. **Move the gate, deliberately and in writing.** Legitimate, since no external
   requirement sets it (see "Two sets of numbers" above), and dishonest if done
   after seeing the score rather than before.

Do the cheap work first either way: the rule gaps and the attribution decision are
worth roughly 0.44 recall between them and cost far less than any of the three.

### Priority 1 — Write Run 4 and score it once  *(holdout-3 is done and burned)*

Nothing else can be judged until this exists. It is measurement, not product,
and it should be done **first** so every later change has a scoreboard.

Partial work is already on disk: `benchmark/holdout-3/` has six family
directories and roughly 74 source files, and one `cases.json`
(`astro-commerce`). The families are `deno-edge`, `bun-runtime`,
`server-functions`, `realtime-desk`, `extension-suite`, `astro-commerce`, and a
`frontier` family that was never started.

Constraints for whoever writes it — from `HOLDOUT-PROTOCOL.md`, and they are not
negotiable if the result is to mean anything:

* the author must not read `packages/scan/`, any existing corpus's case files, or
  `HOLDOUT-PROTOCOL.md` below the "Run 1" heading;
* the author must not run any scanner or scorer while writing;
* the scorer runs **once**, at the end, and the result is recorded whatever it says.

Three lessons from the earlier corpora, each of which cost real measurement:

1. **Keep every case JavaScript or TypeScript.** Holdout-2 put 54 of its 76 cases
   in Python, Java, Ruby and Go, which the engine does not parse; the scorer
   excluded them and left a sample of eleven. A ratio out of eleven concludes
   almost nothing.
2. **Keep the caller-controlled value and the defect in the same function**,
   unless a case is deliberately about a cross-module flow — and mark those in
   the case's `why`. A corpus made mostly of cross-module cases measures a
   capability the static pass does not claim to have.
3. **A case whose `route` is declared in another module must ship that module in
   `extraFiles`.** The scorer scans every case *alone*, deliberately, so a rule
   cannot pass by recognising a neighbour. A route that only exists in the router
   is therefore unmeetable inside the harness — four of holdout-2's remaining
   misses are "detected at the right line, route absent only in the harness".
   Worth adding as a check in `benchmark/build-corpus-manifest.mjs`.

Then:

```bash
node benchmark/build-corpus-manifest.mjs --corpus benchmark/holdout-3   # validates as it merges
node benchmark/score-corpus.mjs --corpus benchmark/holdout-3
```

Record the result in `HOLDOUT-PROTOCOL.md` **before** changing anything in
response to it, and treat the corpus as burned from that moment.

**Cost note.** Two attempts at this corpus spent roughly 1.2M subagent tokens
between them and produced one usable family, because a blind author has to write
a whole realistic application before any of it is scorable and an interrupted
author leaves nothing. Fan-out is the wrong shape here: run **one or two agents
at a time, one family each, sequentially**, and let each finish.

### Priority 2 — ~~Close the known precision defect~~  *(done 2026-08-21)*

One safe case in holdout-2 still produces a finding:

```
h2-modern-js-incident-stream-origin   perimeter-cors at line 46
```

Its vulnerable sibling is `h2-modern-js-deployment-stream-origin`
(`modern-js/pulse/src/sse/deployments.ts`), which reflects a caller-supplied
`Origin` into `Access-Control-Allow-Origin`. Read both files, find what makes the
incidents one correct, and teach `crossOriginPolicy` in
`packages/scan/src/rules/perimeter.ts` the difference. The agent assigned this
died before finishing; nothing was changed, so the ground is clean.

Precision is worth more than recall. This is one case and it is worth doing before
any new recall work.

### Priority 3 — Adapters for the architectures with none

Each is one new file plus one registry line, then a rules pass. Roughly in order
of how much real-world code they represent:

| Architecture | Notes |
|---|---|
| Express-free Node HTTP frameworks not yet covered | Check `frameworks/` first — thirteen exist |
| Effect / `@effect/platform` | Growing fast, entirely unmodelled |
| Encore.ts | Service definitions, typed endpoints |
| Convex | `mutation` / `query` handlers, args are caller data |
| Adonis, Feathers, Moleculer | Controller and service shapes |
| Temporal / Inngest steps | The input arrived from a public endpoint upstream |
| Meteor methods | `Meteor.methods({ name(args) })` |

Before writing any of these, check whether the `frontier` family of holdout-3
covers it — that family exists precisely to measure the frontier, and an adapter
written after reading its cases is tuning, not generalising.

### Priority 4 — Two scope decisions that need a human

Neither is volume work; both change what the product claims.

**Non-JavaScript languages.** Python, Java, Ruby and Go are not parsed at all.
For a Django or Rails shop the report currently assesses almost nothing. The
engine now says so in its coverage output, which is honest but is not a fix.
Options, roughly ascending in cost:

* leave it, and make the limitation louder at the top of the report;
* entry-point and sink recognition only, per language, with no taint — cheaper,
  but a half-quality analyser that produces false positives is worse than an
  honest silence;
* a real per-language front end behind the existing `RuleContext`, which is a
  large piece of work and the only option that reaches parity.

**Cross-module data flow.** Deliberately the host agent's job today. If that
changes, it is an architectural addition (a module graph, and taint that crosses
it), not a rule change. `packages/scan/src/ast/route-index.ts` is the precedent
worth copying: it reads other modules for *route attribution only*, resolves
imports to paths rather than matching names, and refuses to answer when a handler
is registered under two different paths.

---

## 5. Things that are easy to get wrong

Each of these was got wrong during the work that produced this plan.

* **`String()` is not a sanitiser.** `String(x)` on a string returns that string.
  It belongs in the pass-through list, and it is there. Adding it to
  `UNIVERSAL_SANITIZERS` silently hides injection wherever a developer wrote the
  defensive-looking coercion.
* **Server-attached properties are one level deep.** `request.user` is the
  authenticated subject; `request.body.user` is a field the caller named. Walking
  the whole dotted path disarmed taint for any request field called `state`,
  `account`, `auth`, `tenant`, `identity` or `subject`.
* **Bindings and collections must be analysed in alternating rounds.**
  `const sql = clauses.join(…)` written *above* the `clauses.push(…)` that taints
  it binds nothing on a single pass, and that is the most common shape SQL
  injection actually takes.
* **A JWT `verify` only speaks for a `decode` in the same function.** A file
  routinely holds a correct helper beside a handler that decodes and trusts;
  matching on the argument's text alone reported the file as safe.
* **`process.stderr.write` is not a response.** `write` has to be in the
  response-writer list — it is how a raw `node:http` handler answers — and it is
  also how every program in Node logs. Reporting a handler that logs the error
  and returns a fixed string is the most insulting false positive this engine can
  produce.
* **Orphaned fixture servers make the benchmark look broken.** If
  `node benchmark/run.mjs` suddenly takes 600s instead of 17s, check for stray
  `node src/server.js` processes from interrupted runs holding ports:
  `lsof -nP -iTCP -sTCP:LISTEN | grep node`.

---

## 6. Definition of done

Detection is done when **all** of these hold:

1. A corpus nobody tuned against clears whichever target the project has
   deliberately chosen — see "Two sets of numbers" in Section 1. The enforced one
   is the scorer's: critical/high recall ≥ 0.95, overall recall ≥ 0.90, precision
   ≥ 0.90, safe-decoy false positives ≤ 0.03.
2. That corpus was authored under the protocol's constraints, scored once, and
   the result recorded before any change was made in response.
3. The development corpus and every earlier held-out corpus still pass their
   gates, so nothing was traded away to get there.
4. Scanning this repository's own source, `fixtures/` and `tools/` adds no
   finding that cannot be defended in writing.
5. Per-category numbers are reported, not just an average — an aggregate hides
   the one class that does not work at all, which is the number that matters.
6. Where the engine cannot see something, the report says so in its own coverage
   output rather than returning a clean result and letting silence read as safety.

Point 6 already holds. Points 1 and 2 are the work.
