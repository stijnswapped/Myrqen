# Report schema and presentation

Canonical machine schema: `schemas/report.schema.json` and `schemas/finding.schema.json`.

## Report identity
- stable local report ID;
- optional cloud report ID;
- schema version;
- generated timestamp;
- project/workspace display metadata safe for report;
- requested/resolved effort;
- agent/model/version metadata;
- token usage with provenance;
- duration and phase coverage.

## Finding fields

Required:
- id
- title
- category/CWE-like taxonomy identifiers when justified
- severity: critical|high|medium|low|info
- verification: verified|strong_evidence|needs_review
- summary/root cause
- affected component/location
- impact
- evidence entries
- remediation
- verification/retest plan

Optional:
- relevant sanitized code snippets/diff context;
- request/response excerpts after redaction;
- local reproduction notes;
- related findings/dedupe evidence;
- fixed status and verification revision.

## Evidence quality

Evidence should explain why the finding is believed, not merely restate the category. Mark whether evidence is source-based, runtime-observed, differential between identities, configuration-based, or dependency-derived.

## One source for every number

`packages/report/src/facts.ts` derives every count, the run attribution, the duration, and the generated timestamp. `buildReport` writes `summary` with it and every format reads it; `packages/report/test/consistency.test.mjs` reads the numbers back out of each rendered artifact and holds them to it. Counts are printed, never animated. A run with no named agent whose findings all came from the static pass is labelled "No agent — static pass only", never "unknown". See ADR 016.

## Verdict first

Every human format opens with the verdict, and `report.verdict` carries it for machines (`packages/report/src/verdict.ts`):
- one-line headline and the counts behind it;
- a next step — for a run no agent drove, "Run /myrqen inside your coding agent";
- "Fix these first": at most three open findings, ranked by severity discounted by verification state (a verified high outranks a critical on strong evidence), each with severity, verification, `file:line` / route, a one-line reason, and a short paste-ready prompt (`buildQuickFixPrompt`);
- the binding line: a clean report is not evidence that an application is secure.

Renderers recompute the verdict from the findings they are given and never trust the stored copy, so a projection can never leak a withheld finding through it.

## Compliance mapping

`packages/report/src/compliance.ts` maps every category to CWE, OWASP Top 10:2021 and 2025, and ASVS 4.0.3 / 5.0.0 requirement ids (`v4.0.3-5.3.4`, `v5.0.0-1.2.4`) where a requirement states the preventing control. `finding.compliance` stores it; HTML and Markdown show it per finding and as an aggregated Compliance section; SARIF carries it as rule/result `tags` (`external/cwe/cwe-89`, `owasp-top10-2025/A05`), rule `helpUri`, and a CWE taxonomy. A test fails if the scanner can emit an unmapped category.

## Baseline

`.myrqen/baseline.json` (committable; written by `myrqen baseline`) records known findings by a line-independent fingerprint: category, file, the sink the evidence names, and route. `session finish` compares against it: `finding.baselineState` is `new` or `unchanged`, `report.baseline` lists what has gone, and SARIF sets `baselineState`. "Gone" means not reported by this scan, never verified fixed.

## Local HTML

Offline-capable single artifact or self-contained folder. No CDN scripts, trackers, external fonts, or network requests. Monochrome with one accent: green `#4ade5a` means verified or passed and nothing else; severity is carried by glyph, weight, and grey tone. Light and dark follow the reader's system; print is black on white. Include:
- verdict card first;
- summary header;
- severity/verification filters;
- finding navigation;
- expandable evidence;
- code display;
- Copy prompt to fix button;
- limitations/coverage;
- branded footer.

## Exports

- JSON: canonical structured report.
- Markdown: portable human report.
- SARIF: map findings conservatively; do not invent line locations/rule IDs.
- HTML: polished local primary artifact.
- PDF: branded server/local export when robust rendering is implemented.

A shared/exported report must use the viewer-specific projection before format generation.
