# Effort modes

Effort changes assessment policy, not access rights. Safety/authorization rules never become weaker at higher effort.

## low

Goal: fast developer signal.
- rapid repo map;
- high-signal source/config/secret/dependency checks;
- focused local runtime smoke where available;
- validate obvious high-impact candidates;
- minimal parallelism and limited exploratory branches.

## high

Goal: serious default manual-like pass.
- broader route/auth/data-flow analysis;
- targeted runtime validation;
- access-control identity comparisons;
- deeper validation/dedupe;
- remediation context.

## xhigh

Goal: deeper adversarial exploration for important pre-release checks.
- multiple reasoning/validation passes;
- wider business-logic and cross-route analysis;
- more identity/state combinations;
- stronger independent confirmation before closing important hypotheses.

## ultra

Goal: maximum practical local depth within safety/time bounds.
- comprehensive source/runtime surface mapping;
- repeated validation and alternative-path analysis;
- broad local test matrix;
- extra false-positive challenge pass;
- detailed coverage/limitations.

Ultra must still terminate. Define a configurable practical wall-clock/operation budget and show progress rather than silently looping.

## auto

Resolve based on repo size, application surface, detected auth/roles, runtime availability, recent report context if local and permitted, and user interaction cost. Record both `requested=auto` and the resolved policy parameters.

## Metrics

Record effort requested/resolved, duration, phase timings, candidate/validated counts, agent/model, token provenance, and cancellation/failure. Use these metrics to compare quality and cost without forcing effort modes into fixed token quotas.
