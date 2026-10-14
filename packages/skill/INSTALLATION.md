# Agent skill installation

`packages/skill/myrqen` is the single behavioral source of truth. Vendor locations
receive a copy of the same bundle; there are no forked methodologies.

`myrqen link` and `myrqen install` write the bundle to the locations each agent
actually reads (verified against current vendor documentation, August 2026):

| agent | location |
| --- | --- |
| Claude Code (personal) | `~/.claude/skills/myrqen/` |
| Claude Code (project) | `<repo>/.claude/skills/myrqen/` |
| Codex CLI (personal) | `~/.agents/skills/myrqen/` |
| Codex CLI (project) | `<repo>/.agents/skills/myrqen/` |
| OpenCode | `~/.config/opencode/skills/myrqen/` |
| Portable | `~/.agents/skills/myrqen/` |

Notes:

- Claude Code derives the slash command from the **directory** name, so the bundle
  installs as `myrqen/` and is invoked as `/myrqen auto`. The frontmatter `name` is
  the display label. `$ARGUMENTS` carries the effort.
- OpenCode also reads `.claude/skills` and `.agents/skills`, so a single install can
  satisfy several agents, and `.agents/skills` is why the Codex adapter writes there
  rather than under `~/.codex`.
- Codex has no slash-command mechanism in current documentation, so the universal
  `myrqen auto` invocation is the documented path there.
- A directory Myrqen manages carries a `.myrqen-managed.json` marker naming the
  bundle version, which is how a later run recognises its own work and reports
  "unchanged" instead of rewriting a bundle that already matches. A directory of the
  same name that carries no marker belongs to somebody else: the plan blocks on it
  and says so, and nothing is moved or overwritten until the user has dealt with it.
- `myrqen doctor` reports which integrations are present. A missing convenience
  integration does not mean the scanner is broken: the universal CLI works from any
  agent with shell access.
