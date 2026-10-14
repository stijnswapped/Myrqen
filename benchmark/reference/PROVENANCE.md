# Reference corpus — provenance and integrity notes

Every family is authored by an agent blind to `packages/scan/**`, to every other corpus, to
the other families, and to `benchmark/split.mjs`. No author runs a build, test, scanner,
linter or typechecker. The rules are in the brief each author is handed; the notes below
record where reality departed from them.

## Batch 1 — 2026-08-27

| Family | Split | Cases | Notes |
|---|---|---|---|
| `grpc-service` | holdout | 6 + 6 | See integrity note 1 |
| `mcp-tools` | dev | 6 + 6 | First attempt was interrupted after the source was written but before `cases.json`; the file it had already written was complete and was kept |
| `payload-cms` | dev | 6 + 6 | Second attempt; the first was interrupted before writing anything |
| `sails-waterline` | dev | 7 + 7 | |
| `slack-bolt` | holdout | 6 + 6 | |

Stacks were chosen to span trust boundaries other than HTTP, because six of the seven
single-use corpora were almost entirely HTTP handlers: a Slack app's interaction payloads, an
MCP server's model-supplied tool arguments, and gRPC metadata are three boundaries the
engine had never been measured against.

### Integrity note 1 — `grpc-service` saw blinded path names

The author disclosed, unprompted, that **after** all of its source files were written it ran
a repository-wide `git status --porcelain`, whose output printed *path names* of modified
files under blinded areas (`packages/scan/**`, `benchmark/holdout*`, `docs/internal/**`). No
blinded file was opened and nothing in the family was authored after that command.

Kept, with the disclosure recorded, for three reasons. The information was path names, not
contents. It arrived after the authoring decisions it could have influenced. And the value
of a blindness protocol is that violations are reported rather than hidden — discarding a
disclosed, post-hoc, contents-free observation would teach the next author to say nothing.

A reader who wants to discount this family entirely can: it is one of two holdout families
in batch 1, and the split file identifies it.

### A family with no ground truth is unusable

The first `grpc-service` attempt was interrupted having written 15 source files and no
`cases.json`. Those files were discarded rather than handed to a different author to
annotate: the ground truth has to come from whoever planted the defects, or the corpus
records one agent's guess about another's intent. The brief now tells authors to write
`cases.json` first in outline and fill it in as they go.


## Batch 2 — 2026-09-02

| family | split | cases | notes |
|---|---|---|---|
| `feathers-crm` | holdout | 6 + 6 | Feathers 5, MongoDB adapter, hooks |
| `loopback-inventory` | holdout | 6 + 6 | LoopBack 4, PostgreSQL juggler datasource |

Both landed in the holdout. The split is a hash of the directory name and nobody chose it;
two families falling the same way is a one-in-four outcome and was not steered. The names
were picked from the stack, not from what they would hash to.

Added to make **precision** measurable. The agent measured in ruling U9 flagged 17 of 19
correct files, and 19 safe cases cannot resolve whether any intervention improves that. These
two families take the corpus to 43 safe cases.

Stacks chosen because no earlier corpus used them and each has an authorization idiom of its
own: Feathers expresses authentication and ownership as hooks and distinguishes external from
in-process calls through `params.provider`; LoopBack binds a client-supplied query filter
straight to a repository through `@param.filter` and applies `@authenticate` per class or per
method.

### Integrity note 2 — this batch's author is not blind to the engine

The author brief asks for someone blind to `packages/scan`. **The author of this batch is
not**: the same session had spent days inside the engine's rules, including fixing two
false positives in `rules/perimeter.ts` the day before.

Recorded rather than papered over, with what it does and does not compromise:

- **For the static pass, treat these two families as weaker evidence than batch 1.** A
  non-blind author can unconsciously write defects shaped like the ones the engine already
  finds, or safe code shaped like what it already ignores.
- **For the agent, the blindness that matters is intact.** These families exist to measure an
  agent's precision, and the author has no knowledge of that agent's weights, prompting or
  prior answers, has never seen its output on these cases, and wrote every case before any
  agent ran against them. Nothing about the agent was tuned, at any point, against anything.
- The engine was **not run against these files while they were being authored**, so no case
  was adjusted after seeing whether it was detected.

The measured outcome is consistent with the second point rather than the first: the static
pass finds 1 of the 24 vulnerable cases in the grown holdout, which is what run 7 predicts
for two frameworks it has no adapter for, and not what a corpus quietly fitted to the engine
would look like.

### One pair was authored wrong and caught before it shipped

The first version of `feathers-crm` pair 4 had a vulnerable file guarding with
`if (!context.params.provider) return next()` and a safe file guarding with
`if (isExternal(context)) return authenticate(...)`. Those are the same condition written two
ways, so **neither file was vulnerable and the pair measured nothing**. It was caught by
re-reading the two files against each other before the manifest was built.

Rewritten around the defect Feathers applications actually have: an Express route that calls
`app.service(...).create(data)` with no params, so every hook gating on `provider` concludes
the request came from in-process code and the JWT check is skipped.

Worth recording because a near-miss pair that differs only cosmetically is invisible in every
aggregate — it reads as one detected case and one correctly-ignored case, exactly like a pair
that works.
