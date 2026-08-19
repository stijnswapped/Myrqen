# ADR 014: An explicit sync-decision handshake for non-interactive agents

Status: Accepted.

Context: the scan protocol requires asking "sync this scan?" exactly once, before assessment, and only when quota allows. The CLI is usually launched by a coding agent in a shell with no terminal, where it cannot prompt and must never assume yes.

Decision: when quota is available and there is no TTY, `session start` returns cloud state `decision_required` with an instruction telling the agent to ask the user in the product's own words and then run `myrqen session sync-decision yes|no`. With a TTY the CLI asks directly. When quota is exhausted, no question is asked in either mode and the state is `quota_blocked`.

Consequence: the human is always the one who decides, the question is asked once, and a non-interactive environment never silently opts in or out. The decision is recorded in session state, so a resumed session does not ask again.
