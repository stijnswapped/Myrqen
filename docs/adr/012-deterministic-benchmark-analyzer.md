# ADR 012: A deterministic analyzer stands in for the host agent in benchmarks

Status: Accepted.

Context: `docs/09-testing/BENCHMARK-PLAN.md` requires repeatable measurement of recall, precision, duplicates, calibration, safety violations, and canary leakage. In the product the host agent supplies the reasoning, which is not repeatable.

Decision: `benchmark/analyzer.mjs` performs a fixed source-plus-runtime assessment of the owned fixtures and drives the real CLI through the real scan protocol. It plays the agent's role; nothing about the CLI, policy, dedupe, reporting, or scoring is stubbed.

Consequence: the harness measures the parts of quality Myrqen actually owns — the contract, the gates, the dedupe, the report — with zero variance, and it is the regression gate for safety violations and secret leakage. Model-versus-model comparison is a separate exercise that runs real agents over the same fixtures and ground truth.
