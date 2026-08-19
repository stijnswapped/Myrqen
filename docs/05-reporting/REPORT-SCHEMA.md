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

## Local HTML

Offline-capable single artifact or self-contained folder. No CDN scripts, trackers, external fonts, or network requests. Include:
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
