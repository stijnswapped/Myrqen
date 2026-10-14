# Myrqen

**Security testing, inside the coding agent you already use.**

Myrqen turns your coding agent into a structured application security reviewer.
The agent supplies the reasoning; Myrqen supplies the methodology, the safety
gates, a static analysis pass, the finding contract, and the report. There is no
second LLM API key, and your source does not leave your machine unless you ask
it to.

```bash
npx myrqen@latest
```

That is the whole first step. It detects the coding agents installed on your
machine, shows you exactly which files it would write, asks, and then sets them
up.

---

## 30-second quickstart

```
$ npx myrqen@latest

Myrqen link

Project
  ~/projects/acme-api

Environment
  macOS
  Node 22.11.0
  Myrqen 0.3.0

Detected coding agents

  ● Claude Code       Confirmed  2.0.14
  ● Cursor            Confirmed
  ● GitHub Copilot    Confirmed
  ○ Gemini CLI        Not detected
  ○ Kiro              Not detected

Where should Myrqen be linked?
  ◉ Recommended — all detected agents
  ○ Select agents
  ○ Shared AGENTS.md only
  ○ Nothing for now

Ready to link Myrqen

Claude Code · this project
  CREATE  .claude/skills/myrqen/SKILL.md
  MERGE   CLAUDE.md            existing content preserved
Cursor · this project
  CREATE  .cursor/rules/myrqen.mdc
GitHub Copilot · this project
  CREATE  .github/instructions/myrqen.instructions.md

4 file(s) will change, 1 of them keeps the content already in the file,
no existing instructions are removed.

Continue? [Y/n]
```

Then, in your agent:

```
/myrqen auto
```

or from any agent that can run a shell command:

```bash
myrqen auto
```

The scan runs locally against a project you own. It writes HTML, JSON, Markdown
and SARIF into `.myrqen/reports/`, and hands you a remediation prompt your agent
can apply and re-test.

---

## What Myrqen actually does

| | |
|---|---|
| **Runs locally** | The scan happens on your machine, driven by your agent. Nothing is uploaded unless you answer yes to one explicit question per scan. |
| **Uses your agent's reasoning** | No second model, no separate API key, no per-scan inference bill. |
| **Refuses to be destructive** | No denial of service, no mass mutation, no credential attacks, no scanning of infrastructure you did not name. Higher effort never relaxes this. |
| **Treats your code as data** | A README, a comment, or an API response cannot grant scope, authorize a target, or change the policy. Attempts are recorded as findings. |
| **Says what it did not check** | Every report carries its own coverage and limitations. Silence is never presented as safety. |

---

## What a finding looks like

Real output, from the deliberately vulnerable fixture in the repository. Every
finding carries a severity **and**, independently, a verification state — because
"how bad if real" and "how sure it is real" are different questions and a report
that collapses them is lying about one of them.

```
MYR-004   high · verified
orders is read by identifier without checking who owns it
GET /api/orders/:id  ·  src/server.js:95

  This handler establishes who the caller is, then addresses a single row in
  `orders` using `id` — a value the caller supplies — as the only condition
  that selects it. The authenticated subject is not part of the predicate,
  nothing between the statement and the response compares the row's owner to
  that subject, and the row is returned to the caller.

  Evidence
    source  src/server.js:95
      if (!user) return json(response, 401, { error: "sign in first" });
      const id = Number(url.pathname.split("/").pop());
      const order = orders.find((candidate) => candidate.id === id);
      if (!order) return json(response, 404, { error: "not found" });
      return json(response, 200, order);

    reasoning
      The route establishes an identity and declares no object-level guard.
      `orders` is addressed by a primary-key predicate whose value classifies
      as caller-supplied, the predicate names no owner column, the row reaches
      the response, and no ownership comparison stops the handler.
```

`verified` means an agent exercised it against the running application under a
second identity and got the other account's row back. A candidate nobody
exercised stays `needs_review` and says so — it is never promoted to make the
report look better.

---

## What it does not cover

The honest part. All of it is also printed in every report's own **Coverage and
limitations** section, so you do not have to remember it.

| | |
|---|---|
| **Recall is 0.250 against a gate of 0.90** | A corpus of 64 cases across five frameworks and five data layers, written in parallel by authors who had never read the engine, scored once against a build frozen at a recorded hash and verified unchanged. The figure requires a finding to agree with the case's own CWE *and* land within eight lines of the line its author named; allowed anywhere in that author's marked range it reads the same. Seven held-out runs are recorded and none has reached the gate. **A report with no findings is not evidence that your application is secure.** |
| **Recall depends on what the defect reaches** | **0.875** where the dangerous value flows into a language or runtime primitive — a URL fetch, a filesystem path, a shell, `eval` — and **0.042** where it flows into a framework's own database or identity call. `fetch` and `path.join` are the same in every stack; a query builder is not. Expect much better results on a defect whose sink is JavaScript than on one whose sink is your framework's vocabulary. |
| **Most of what is reported is worth reading, and correct code is sometimes flagged** | On the four older corpora no deliberately-correct file produces a finding. On the most recent held-out corpus 4 of 32 do — 2 a rule asserting a defect that is not there, 2 a rule asking for a look. Precision as a ratio is not computable on those corpora — their authors named every defect in their own vocabulary — so the false-positive rate is the number quoted. |
| **Every figure above is the static pass** | Scored one file at a time with no agent involved. What your agent adds on top of it has never been measured against a corpus, so there is no whole-product recall number to quote. |
| **JavaScript, TypeScript, and Python for FastAPI and Flask** | Other Python frameworks (Django, class-based views, aiohttp, Tornado) are parsed, but their routes are not modelled, and Python dependencies are not checked against advisories. Java, Ruby, Go, templates, and infrastructure definitions are not parsed at all. |
| **Python is newer and measured separately** | On 62 held-out FastAPI and Flask cases, scored once, recall was 0.774 and precision 0.923, and 2 of 31 deliberately correct files were flagged. Those cases have since been read and fixed against, so this is the most recent blind Python figure rather than a measurement of the current engine, and the next one waits on a new held-out set. They cover only the classes the Python engine was built for, so the figure is not comparable with the JavaScript one above. |
| **JavaScript data flow is followed inside a function** | A value that becomes attacker-controlled in one module and reaches a sink in another is not connected by the static pass. Your agent can still find it; the engine will not claim to have. |
| **Dependency checks are shallow** | Declared versions against a small offline advisory table. No lockfile resolution, no reachability. This is not software composition analysis. |
| **No destructive testing, at any effort** | There is no opt-in flag in this release. |

Methodology, per-class results, and the raw scoring output:
<https://myrqen.cc/benchmarks>.

---

## Supported agents

Every agent below is detected automatically and configured through the
integration format its own documentation describes.

<!-- agent-matrix:start -->

| Agent                                                                                          | Auto-detect | Project | Global | Native format     | `--agent` id     |
|------------------------------------------------------------------------------------------------|-------------|---------|--------|-------------------|------------------|
| [Claude Code](https://code.claude.com/docs/en/skills)                                          | Yes         | Yes     | Yes    | Agent skill       | `claude-code`    |
| [Codex CLI](https://learn.chatgpt.com/docs/agent-configuration/agents-md)                      | Yes         | Yes     | Yes    | Agent skill       | `codex`          |
| [Cursor](https://cursor.com/docs/context/rules)                                                | Yes         | Yes     | —      | Rules file        | `cursor`         |
| [GitHub Copilot](https://code.visualstudio.com/docs/copilot/customization/custom-instructions) | Yes         | Yes     | Yes    | Instructions file | `github-copilot` |
| [Gemini CLI](https://geminicli.com/docs/cli/gemini-md/)                                        | Yes         | Yes     | Yes    | Managed section   | `gemini-cli`     |
| [Windsurf](https://docs.devin.ai/desktop/cascade/memories)                                     | Yes         | Yes     | Yes    | Rules file        | `windsurf`       |
| [Cline](https://docs.cline.bot/features/cline-rules)                                           | Yes         | Yes     | Yes    | Rules file        | `cline`          |
| [Roo Code](https://roocodeinc.github.io/Roo-Code/features/custom-instructions)                 | Yes         | Yes     | Yes    | Rules file        | `roo-code`       |
| [Continue](https://docs.continue.dev/customize/deep-dives/rules)                               | Yes         | Yes     | Yes    | Rules file        | `continue`       |
| [Kiro](https://kiro.dev/docs/steering/)                                                        | Yes         | Yes     | Yes    | Agent skill       | `kiro`           |
| [Aider](https://aider.chat/docs/usage/conventions.html)                                        | Yes         | Yes     | —      | Rules file        | `aider`          |
| [OpenCode](https://opencode.ai/docs/skills/)                                                   | Yes         | Yes     | Yes    | Agent skill       | `opencode`       |
| [Shared AGENTS.md](https://agents.md/)                                                         | Yes         | Yes     | —      | Instructions file | `agents-md`      |

<!-- agent-matrix:end -->

"Auto-detect" means Myrqen looks for the agent using several independent
signals — an executable present on `PATH`, an installed application, an
extension in an editor's extensions directory, a documented configuration
directory — and tells you how sure it is. A configuration directory on its own
is reported as *probable* rather than *confirmed*, and probable agents are
offered but not pre-selected.

**Every one of those signals is a file that exists.** Detection reaches its
verdict without starting a single process, because starting one is not free:
some agent CLIs bootstrap themselves the first time they run, writing hundreds
of files into your home directory. Finding out which agents you have must not
install anything.

Detection never opens a credential store, a token file, or a conversation
history. It asks whether a path exists.

### Version probing

The version printed beside an agent is the one exception, and it is optional,
second-class, and off by default in every unattended run.

- It is read by running `<agent> --version`, which means **that agent's own CLI
  runs on your machine and may do whatever it likes** — including, for at least
  one agent, unpacking itself into your home directory.
- It happens only when the agent is *already* confirmed by a signal that
  executed nothing, only for commands whose version flag Myrqen has recorded as
  inert, and never for GitHub Copilot's CLI, which is opted out by name.
- Nothing depends on it. A missing version costs you a string in a table and
  changes no verdict, no plan, and no file.

| | Probing |
|---|---|
| An attended terminal | on |
| `CI` is set, or output is piped or redirected | off |
| `--no-probe` on `link`, `install`, `status`, or `doctor` | off, always |
| `MYRQEN_NO_PROBE=1` | off |
| `MYRQEN_PROBE=1` | on, even unattended |

`--no-probe` outranks everything, including `MYRQEN_PROBE=1`.

Editor extensions work the same way round. The extensions directory is read
first, always, and when it answers no editor is started at all. `code
--list-extensions` is consulted only if that misses *and* probing is on, so one
case is genuinely worse off: an editor launched with a non-default
`--extensions-dir`, on a run that may not probe, is reported one confidence level
lower instead of being started to find out. That is the trade, stated plainly —
Myrqen would rather under-claim than launch your editor.

`myrqen doctor` always reports which of these applied and names anything it ran.

---

## What `link` changes

This matters more than anything else in this README, because Myrqen writes into
files you own.

1. **You choose.** Nothing is written before the plan is printed and you accept
   it. `--dry-run` prints the plan and stops. If detecting your agents ran
   anything, the dry-run summary names it — the promise is that *Myrqen* wrote
   nothing, and a run that launched somebody else's CLI says so in one line
   rather than letting "nothing was written" be read as "nothing happened".
2. **Dedicated files where the format allows one.** `.cursor/rules/myrqen.mdc`,
   `.github/instructions/myrqen.instructions.md`, `.claude/skills/myrqen/` —
   Myrqen owns these outright and removing them removes Myrqen.
3. **Managed regions where the format is a shared file.** In `AGENTS.md`,
   `CLAUDE.md`, `GEMINI.md` and `.github/copilot-instructions.md`, Myrqen owns
   only the region between its markers:

   ```markdown
   <!-- myrqen:start v2 -->
   ...
   <!-- myrqen:end -->
   ```

   Everything else in the file — including formatting, comments, blank lines
   inside code fences, a byte-order mark, and CRLF line endings — is left exactly
   as it was. `myrqen link` followed by `myrqen unlink` returns the file byte for
   byte, and there is a test that asserts precisely that.

   A marker only counts when it is alone on its own line, so a file that merely
   *writes about* the markers — a README, a changelog, this section quoted into
   your own docs — is not mistaken for a managed region.
4. **Idempotent.** Run `myrqen link` again and it reports *already up to date*.
   It never appends a second copy.
5. **Small.** An always-on instructions file gets about 25 lines: enough to make
   your agent reach for Myrqen at the right moment. The full methodology is
   thousands of tokens and lives in an on-demand skill, so it costs you nothing
   in the conversations that are not about security.
6. **Reversible.** `myrqen unlink` removes only Myrqen's own content and deletes
   a file only when the whole file was Myrqen's.

---

## Commands

```
myrqen                  Guided setup — the same as `myrqen link`
myrqen link             Detect coding agents and configure the ones you choose
myrqen status           Show which agents are detected, linked, and healthy
myrqen doctor           Diagnose setup problems and say how to fix each one
myrqen unlink           Remove Myrqen integrations safely
myrqen login            Connect an account for cloud reports (optional)
myrqen logout           Remove the local device credential

myrqen auto             Run an assessment at automatically chosen effort
myrqen low              ...at low effort
myrqen high             ...at high effort
myrqen xhigh            ...at very high effort
myrqen ultra            ...at maximum effort

myrqen watch            Follow a scan your agent is running, live, from a second terminal
myrqen report           Open the latest HTML report (--format md|json|sarif, --list)
myrqen diff             What changed since the last run: new, fixed, regressed, still open
myrqen fix <id>         Fix one finding on its own branch; commits only after a retest passes
myrqen retest <id>      Re-run only that finding's check
myrqen config           How this project's app is started (asked once, then remembered)

myrqen reports          List local reports and their cloud state
myrqen doctor           What this machine and agent setup can assess
myrqen --help
myrqen --version
```

`myrqen session`, `myrqen finding`, `myrqen target`, `myrqen phase`,
`myrqen note`, `myrqen metrics` and `myrqen fix` are the protocol your agent
drives during a scan. `myrqen --help` lists them; you do not need to type them
yourself.

### Automation

```bash
myrqen link --agent claude-code --agent cursor --scope project --yes
myrqen link --all --scope project --yes
myrqen link --dry-run
myrqen link --all --scope project --yes --no-probe
myrqen --json status --agents
myrqen unlink --all --yes
```

With `--json`, stdout is JSON and nothing else — including on the error paths,
where the reason arrives as `{"error": {"code": …, "message": …}}` rather than as
prose on stderr. `--json` never prompts, so it needs the agents named
(`--agent <id>` or `--all`) and an explicit `--yes` before it writes anything;
without `--yes` it prints the plan it would apply and exits 2.

Interactive prompts turn themselves off when stdout is not a terminal, and
`NO_COLOR`, `CI` and `TERM=dumb` are honoured — a CI runner that allocates a pty
is still a shell with nobody in it, so nothing waits for a keypress there. In a
non-interactive shell with no flags, `link` changes nothing and names the flag to
pass, listing the agents it detected. It never chooses on your behalf.

Detection executes nothing in these runs either: `CI`, and stdout not being a
terminal, each turn version probing off, so an automated `link` or `status`
starts no agent CLI. `--no-probe` says the same thing explicitly and outranks
everything. With `--json`, every document carries a `probe` object — `allowed`,
`reason`, and `executed` — so a caller diffing its home directory afterwards can
see exactly which programs the command started. See
[Version probing](#version-probing).

Exit codes: `0` when the requested work was done, `1` when a write failed, and
`2` when the request could not be met at all — an unknown agent, a scope an
adapter does not support, or a `--json` run with nothing selected.

---

## Installing

### Zero install

```bash
npx myrqen@latest
```

### Global

```bash
npm install -g myrqen
myrqen
```

### Other package managers

Verified against the real package by `node scripts/verify-tarball.mjs`, which
installs it into an empty project and runs a full link and unlink round-trip
under each one:

```bash
bun add myrqen && bunx myrqen      # Bun
pnpm dlx myrqen                    # pnpm
```

`yarn dlx` is **not** listed because it has never been run against this package.
It very likely works; "very likely" is not a thing to put in a README.

### Requirements

Node.js 20.12 or newer. macOS, Linux, Windows, and WSL.

The package is a single self-contained bundle plus the agent skill. It has no
runtime dependencies.

---

## Updating and removing

**The CLI**

```bash
npx myrqen@latest        # always the current release
npm update -g myrqen     # if you installed globally
```

**The integrations.** When Myrqen's payload changes between releases,
`myrqen status` reports `update available` and `myrqen link` rewrites only the
managed region:

```bash
myrqen link
```

**Removing.** `myrqen unlink` removes Myrqen's files and managed regions and
nothing else. It never touches another tool's configuration directory, never
removes a rule you wrote, and deletes a shared file only if Myrqen's region was
all that was in it.

```bash
myrqen unlink                        # choose what to remove
myrqen unlink --scope project --all  # only this repository
myrqen unlink --all                  # everywhere, including global integrations
npm uninstall -g myrqen              # then remove the CLI itself, if it was global
```

Without `--scope`, `unlink` removes the integrations for the agents you name in
**every** scope they are installed in, global included. The plan says so before it
runs; `--yes` skips the plan, so pass `--scope project` when you mean this
repository only.

---

## Troubleshooting

Start here:

```bash
myrqen doctor
```

It checks the CLI, the Node version, the project root, file permissions, every
installed integration, and the agents it can see, and it tells you what to do
about each problem rather than only that there is one.

| Symptom | What is happening |
|---|---|
| `myrqen: command not found` | The global install is not on your `PATH`. Use `npx myrqen@latest`, or add npm's global bin directory to `PATH`. |
| `EACCES` during `npm install -g` | npm's global directory is not writable. Use `npx`, or a Node version manager, rather than `sudo`. |
| An agent you have is "Not detected" | Its executable is not on `PATH` and its configuration directory does not exist yet. Install it for that agent explicitly: `myrqen link --agent <id>`. |
| An agent you do not have is listed | Detection found a leftover configuration directory. It is reported as *probable* and is not selected by default. |
| No version beside an agent | Probing is off — the default whenever `CI` is set or output is not a terminal. The version is cosmetic; nothing else changes. Set `MYRQEN_PROBE=1` if you want it. |
| `link`, `status`, or `doctor` is slow, or something appeared in `~` | An agent's own CLI was launched for its version and did more than print. Run with `--no-probe`, or set `MYRQEN_NO_PROBE=1`, and tell us which agent so it can be opted out by name. |
| "not a repository" or the wrong project | Myrqen walks up for a `.git` directory. Run it from inside the project. |
| A managed region will not update | `myrqen doctor` will name the file. Two managed regions in one file are reported as *conflicted* and are never merged automatically — delete one and run `myrqen link` again. |
| Permission denied writing a rule file | The file is read-only, or its directory is not writable. The plan reports it as `BLOCKED` with the path and the reason, before you approve anything, and every other integration still installs. |
| "the file is not valid UTF-8" | Myrqen reads and rewrites a whole instruction file, so a file in Latin-1 or Shift-JIS would lose the bytes that are not valid UTF-8. It refuses instead. Convert the file, or add the section by hand. |
| A `CLAUDE.md` that is a symlink | Myrqen writes *through* the link, so a shared instructions file stays shared. The link is never replaced with a copy. |
| Windows or WSL confusion | Myrqen writes to the home directory of the environment it runs in. Run it inside WSL for WSL agents, and in Windows for Windows agents. |

---

## Privacy

**Agent detection** is entirely local, and by default it executes nothing at
all. It reads `PATH`, application directories, editors' extensions directories,
and documented configuration directories — existence only. It does not read
`.env` files, credential stores, token files, browser data, or conversation
history, and it never prints a secret.

In an attended terminal it will additionally run `<agent> --version` on agents it
has already confirmed, purely to print a version. **That runs a third-party
program on your machine, and what it does next is that program's business, not
Myrqen's** — one agent CLI is known to bootstrap itself into your home directory
on first launch, and is therefore never executed at all. Turn the rest off with
`--no-probe` or `MYRQEN_NO_PROBE=1`; see [Version probing](#version-probing).

**`link`** reads and writes only the integration files listed in the plan it
shows you. It reads your existing instruction files in order to preserve them.

**Scanning** runs locally. Your agent reads your source; Myrqen's static pass
parses it on your machine. Findings, evidence snippets, and reports are written
to `.myrqen/` inside your project.

**Cloud reports are opt-in per scan.** Myrqen asks once per scan whether to sync.
Answer no and no event leaves the machine. Answer yes and the report — including
the evidence snippets it contains — is uploaded to the deployment you are linked
to. Secret *values* are never placed in a finding, a report, or a progress
message: a secret is described by type and location.

If the deployment cannot be reached, **every scan stays local and says so** rather
than failing. Nothing about the assessment depends on the network: discovery, the
static pass, the safety gates and all four report formats are local work.

Cloud reports need a Myrqen deployment to talk to. If you are self-hosting,
point the CLI at yours:

```bash
myrqen config set-url https://myrqen.internal.example.com
```

---

## Links

| | |
|---|---|
| Documentation | <https://docs.myrqen.cc> |
| Measured accuracy, and how it was measured | <https://myrqen.cc/benchmarks> |
| What runs locally and what does not | <https://myrqen.cc/security> |
| Source | <https://github.com/stijnswapped/Myrqen> |
| Report a vulnerability **in Myrqen** | <https://myrqen.cc/.well-known/security.txt> |
| Bugs and feature requests | <https://github.com/stijnswapped/Myrqen/issues> |

---

## Licence

Source-available, not open source. See `LICENSE`. Copyright is retained and the
licence grants reading and auditing, not reuse.

Myrqen is a working codename pending trademark clearance.
