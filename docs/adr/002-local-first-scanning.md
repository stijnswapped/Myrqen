# ADR 002: Local-first scanning

Status: Accepted.

Decision: source inspection, raw secrets, runtime interaction, and primary assessment execute locally. Cloud receives only opt-in report data and privacy-safe progress.

Consequences: stronger trust story and simpler source privacy; cross-platform local tooling becomes a major engineering responsibility; cloud cannot assume access to repository for fixes.
