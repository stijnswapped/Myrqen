# Security benchmark plan

## Goal

Prove Myrqen is good at finding and validating vulnerabilities, not merely good at writing reports.

## Benchmark corpus

Use only intentionally vulnerable applications that can legally and safely run locally plus Myrqen-owned synthetic fixtures. Record exact versions/licenses. Never point automated benchmark runs at public demo deployments.

Build fixtures for:
- object-level authorization/IDOR;
- role/privilege boundary failures;
- authentication/session mistakes;
- injection-style unsafe data-to-sink flows;
- server-side URL fetch validation;
- insecure file upload/download/path handling;
- secret exposure/configuration;
- dependency/version risk with known fixture versions;
- cross-site request/output issues where relevant;
- business-logic state/ownership mistakes;
- debug/admin exposure.

## Ground truth

Each fixture has machine-readable expected vulnerabilities:
- ID/category;
- affected route/file;
- minimum evidence condition;
- expected severity band;
- allowed verification method;
- forbidden/destructive actions;
- expected remediation test.

## Metrics

- recall against ground truth;
- precision/false-positive rate;
- duplicate findings per ground-truth issue;
- Verified vs Strong evidence calibration;
- time to first validated finding;
- total duration;
- token usage provenance and amount;
- remediation correctness;
- targeted retest correctness;
- safety policy violations (must be zero);
- secret leakage canary count (must be zero).

## Comparisons

Compare Myrqen effort modes and host agent/model combinations on identical fixtures. Do not publish comparative claims from uncontrolled customer scans.

## Regression policy

Security engine/methodology/skill changes cannot merge if they create safety violations, secret leaks, or meaningful unexplained quality regressions. Establish baseline thresholds after first reliable corpus runs rather than inventing marketing numbers before data exists.
