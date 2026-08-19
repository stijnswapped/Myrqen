# Detection corpus

A ground-truth corpus for the static engine in `packages/scan`. It exists to answer
one question honestly: given code that a competent reviewer would flag, does the
product flag it — and given code that is correct, does it stay quiet?

## Shape

```
benchmark/corpus/
  manifest.json          every case, with its ground truth
  <family>/<case>.<ext>  one file per case
  score.mjs              the scorer (in benchmark/, not here)
```

Each case is one file. A case is either **vulnerable** — a defect a reviewer would
report, with the class, the line, and the route it belongs to — or **safe**: code
that a naive scanner mistakes for the vulnerable form, and which must produce no
finding at all.

## Rules for authoring a case

1. **Write the code an engineer would write.** Not the minimal shape that triggers a
   rule. If the vulnerable version needs a route, a session, and a database call to
   be realistic, write all three. A corpus of toy snippets measures a toy.
2. **Never name a case after its defect.** No `sqlInjection`, no `vulnerable`, no
   `unsafe_`. The engine must not be able to pass by reading identifiers, and a
   corpus that leaks the answer in its own names cannot detect that it does.
3. **Every safe case must be a near-miss of a vulnerable one.** A safe case that
   shares nothing with the vulnerable form proves nothing. The pairs are the test.
4. **State the line, and keep it stable.** `line` is where a reviewer would put the
   comment. `lineRange` allows a small window for cases where the sink and the
   composition sit apart.
5. **Say what a runtime probe would need.** `runtimeVerifiable` records whether the
   class can be settled by exercising the application, which is what separates a
   finding from a claim.
6. **A language the engine cannot parse is a limitation, not a miss.** Cases in
   `unsupportedLanguage` families are scored separately and never counted as recall
   failures; they exist so the coverage statement stays true.

## Manifest entry

```jsonc
{
  "id": "express-order-lookup-unscoped",
  "family": "express",
  "architecture": "Express 4 router with middleware authentication",
  "language": "javascript",
  "file": "express/order-lookup-unscoped.js",
  "kind": "vulnerable",
  "category": "broken_object_level_authorization",
  "severityBand": ["high", "critical"],
  "route": "GET /orders/:id",
  "line": 24,
  "lineRange": [22, 27],
  "runtimeVerifiable": true,
  "why": "The lookup resolves the record from the path parameter alone; the authenticated subject is never part of the query."
}
```

A safe case carries `"kind": "safe"`, no `category`, and a `why` that states what
makes it correct — because that sentence is what a reviewer would need in order to
agree that a finding here would be wrong.

## Scoring

```bash
node benchmark/score-corpus.mjs            # all families
node benchmark/score-corpus.mjs --family express
node benchmark/score-corpus.mjs --update-baseline
```

Recall is computed over vulnerable cases, the false-positive rate over safe cases.
Both are reported per class and per family, because an aggregate hides exactly the
class that does not work.
