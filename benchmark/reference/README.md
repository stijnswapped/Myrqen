# The reference corpus

A **growable, permanently split** corpus. Half its families are used freely; the other half
is never tuned against and is scored on every commit.

This replaces the single-use protocol for measuring detection. It does not replace the
rulings in `docs/12-release/HOLDOUT-PROTOCOL.md` about *how* cases are written — those
carry forward unchanged, and the author brief still enforces them.

## Why

Seven held-out corpora were each scored once and burned. The reasoning was right and the
implementation capped the sample at about thirty vulnerable cases forever. Thirty cases give
a 95% interval roughly 0.31 wide, so the three comparable blind figures — 0.300, 0.333,
0.250 — are indistinguishable from one another, and the conclusions drawn from their
differences were drawn from noise. Ruling U7 records that in full, including the two claims
it retracts.

The property that made those corpora trustworthy was never the discarding. It was that
nobody had seen them. That can be held indefinitely for half a corpus, and then the half
that is held can be scored continuously instead of once.

| vulnerable cases in the holdout | 95% interval at p = 0.30 | width |
|---|---|---|
| 30 (the old protocol, permanently) | [0.167, 0.479] | 0.312 |
| 90 | [0.216, 0.396] | 0.190 |
| 150 | [0.232, 0.378] | 0.145 |

## The split

By **family**, from the family's own directory name, in `benchmark/split.mjs`. Nobody
chooses it and anyone can recompute it.

Family-level rather than case-level on purpose: a case-level split leaves both halves
sharing authors, stacks and idioms, so a fix aimed at the development half would silently
improve the holdout and the holdout would report an improvement it had no independent
evidence for.

The split will not be exactly even. Forcing it to be even would mean choosing it.

```bash
node benchmark/build-corpus-manifest.mjs --corpus benchmark/reference   # validate
node benchmark/score-corpus.mjs --corpus benchmark/reference --split dev
node benchmark/score-corpus.mjs --corpus benchmark/reference --split holdout
```

`--split holdout` prints aggregates and **refuses to name a case**. That is enforced in
code rather than asked for: the moment a holdout figure moves, the natural next question is
*which case*, and answering it is what turns a holdout into a development corpus. Per-case
outcomes are also omitted from the holdout's run file for the same reason.

Class-level counts stay visible in both halves. "Nothing detects this class" names a
capability, not a case, and cannot be overfitted to the way a file and a line number can.

## Growing it

Add families. The split is a pure function of the name, so an existing family cannot move,
the holdout only ever gains cases, and every figure stays comparable with the last one.

Each family: 8–14 source files, 5–7 vulnerable cases, 5–7 safe near-miss pairs, authored by
someone blind to `packages/scan` and to the other families. Stacks should be ones no earlier
corpus used, for the same reason as ruling U5 — a fix fitted to one framework's spelling
must not be able to show up as a general improvement.

## What this corpus does not fix

It measures the static pass on hand-authored applications. Two gaps remain, both recorded
in `docs/internal/detection-improvement-plan.md`:

- **Real-world code.** Public vulnerability data at scale (the GitHub Advisory Database is
  CC-BY-4.0 and carries CWEs and fix commits) would be an external-validity check this
  cannot provide. It is also structurally unable to cover the classes this engine is
  weakest at: broken authorization in an application does not become a CVE, so CVE data is
  library data. Measured before anything is built on it.
- **The agent.** `endToEnd.recall` is still null. The product's differentiator is in no
  number published anywhere.
