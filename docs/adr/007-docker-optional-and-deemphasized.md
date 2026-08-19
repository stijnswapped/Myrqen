# ADR 007: Isolation runtime optional and de-emphasized

Status: Accepted.

Decision: use Docker/isolated runtime when available where it improves safety/tooling, but ordinary users are not required to understand or install Docker to receive useful analysis. Capability reductions are explained calmly in coverage/doctor output rather than as recurring scary warnings.
