# ADR 001: Host agent provides LLM inference

Status: Accepted.

Decision: Myrqen scan orchestration uses the model already running in Claude Code, Codex/OpenAI local agent, OpenCode, or compatible host. Myrqen does not require a separate model provider API key.

Consequences: lower user friction/cost; behavior varies by host/model; adapters need capability detection; token metrics may be exact/estimated/unavailable; methodology/contracts must stabilize output across models.
