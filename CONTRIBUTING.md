# Contributing

Read this first, because the licence makes this project unusual and it would be
unfair to let you find out after writing a patch.

**Myrqen is source-available, not open source.** `LICENSE` grants reading,
auditing, and running it for your own work. It does not grant redistribution,
forks, mirrors, or building it into something you ship. If you were hoping to
fork it, this is not that project — and that is a deliberate choice, not an
oversight.

What is genuinely wanted:

| | |
|---|---|
| **Detection defects** | The most valuable contribution there is. A missed vulnerability or a false positive, reduced to the smallest snippet that shows it, becomes a permanent corpus case. Use the [_Detection defect_ issue form](https://github.com/stijnswapped/Myrqen/issues/new/choose). |
| **Security reports** | See [`SECURITY.md`](SECURITY.md). Never a public issue. |
| **Bugs** | Anything in the CLI, an agent integration, or a report renderer. Paste `myrqen doctor`. |
| **Documentation corrections** | Especially anything that is now false. The site spent a release telling people the CLI was not on npm. |
| **A fix** | Accepted, under the terms below. |

## Submitting a fix

By opening a pull request you agree that your contribution is licensed under the
same terms as the project, and that copyright in the combined work is retained by
the copyright holder named in `LICENSE`. There is no separate CLA to sign; this
paragraph is it. If that is not acceptable to you, open an issue describing the
fix instead and it will be implemented separately.

Small, focused changes are far more likely to be merged than large ones. Open an
issue before a large one.

## Local development

Node 20.12 or newer, pnpm 9.15.4, and PostgreSQL 14+ only if you are touching the
hosted half. Docker is not required.

```bash
pnpm install
pnpm build
pnpm test
```

The full gate, which is what CI runs:

```bash
pnpm test:all
```

That is lint, build, typecheck, unit and integration tests, the documentation
check, the deployment shape tests, the scoring harness, the acceptance journey,
the fixture benchmark, and the static-engine corpus. It must be green.

### Never run the CLI against your real home directory

`myrqen link` edits coding-agent configuration, and that is the point of it. When
testing, redirect `HOME`:

```bash
T=$(mktemp -d); mkdir -p "$T/home" "$T/p/.git"
echo '{"name":"p","version":"1.0.0"}' > "$T/p/package.json"
cd "$T/p" && HOME=$T/home XDG_CONFIG_HOME=$T/home/.config \
  MYRQEN_CONFIG_DIR=$T/home/cfg MYRQEN_NON_INTERACTIVE=1 NO_COLOR=1 \
  node /path/to/Myrqen/apps/cli/dist/myrqen.mjs link --dry-run
```

## What a change to the engine has to come with

The scanner's precision is 1.000 and its safe-code false-positive rate is 0.000,
and keeping both there is worth more than a recall point. So a new or changed rule
needs **two** tests: one asserting the vulnerable form is found, and one asserting
that its guarded sibling is silent. A rule with only the first test is how a
scanner becomes something people stop reading.

Then:

```bash
node benchmark/score-corpus.mjs                 # the development corpus
pnpm detection:report                           # every corpus, side by side
```

`pnpm detection:report` prints each corpus with what it cannot say. Quote it
rather than a single number.

### Do not tune against a held-out corpus

`benchmark/holdout`, `holdout-2`, and `holdout-3` have each been scored and are
therefore **burned** — they no longer measure generalisation, and the fact that
they were tuned against is recorded rather than quietly forgotten. If you need a
generalisation measurement, a new corpus has to be authored by somebody who has
not read the engine, and scored exactly once, before anything is changed in
response. `docs/12-release/HOLDOUT-PROTOCOL.md` is the procedure.

## Style

Match the file you are editing. Two things are load-bearing across the codebase:

- **Comments say why, not what.** A comment that restates the code is deleted in
  review; a comment recording the reason a non-obvious decision was taken is the
  most valuable line in the file.
- **Honesty in output.** No message may imply an application is secure because
  nothing was found, no finding may be promoted to `verified` without evidence,
  and no limitation may be omitted from a report because it is unflattering.

`pnpm lint` enforces the mechanical part: no committed secrets, no scattered brand
literals, no TODO-only scaffolding, no debug logging in product code.

## Architecture decisions

A change that alters a boundary — where something runs, what may cross between
the local and hosted halves, what the agent owns versus what the CLI owns — needs
an ADR in `docs/adr/`. Read the existing fourteen first; several of them exist
precisely to stop a plausible-sounding change.
