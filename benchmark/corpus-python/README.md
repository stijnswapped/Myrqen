# Python development corpus

Development data for `packages/scan-python`. The engine was tuned against these
cases and against `benchmark/corpus/python-fastapi`, so a perfect score here is a
regression gate, not evidence about unseen code. `benchmark/holdout-python` was a
held-out corpus until it was fixed against, and is development data too, as is
`benchmark/holdout-python-2` since its second round of fixes. No Python corpus is held out
at the moment; see `docs/12-release/HOLDOUT-PROTOCOL.md`.

Every recorded `line` was computed from the case file text when the corpus was
written, not typed by hand.

```bash
node benchmark/build-corpus-manifest.mjs --corpus benchmark/corpus-python
node benchmark/score-corpus.mjs --corpus benchmark/corpus-python
```
