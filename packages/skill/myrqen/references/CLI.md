# Myrqen CLI surface

Add `--json` to any command for machine-readable output. Add `--session <id>` to act
on a specific local report instead of the current one.

## Session

| command | purpose |
| --- | --- |
| `myrqen <low\|high\|xhigh\|ultra\|auto>` | Start an assessment with that effort. |
| `myrqen session start --effort <effort>` | Same, with explicit flags. |
| `myrqen session context` | Re-read the current session context. |
| `myrqen session sync-decision <yes\|no>` | Record the user's answer to the sync question. |
| `myrqen session agent --name <n> --model <m>` | Record host agent and model metadata. |
| `myrqen session finish` | Validate, write local formats, sync if enabled. |
| `myrqen session cancel` | Finish early, keeping what was validated. |

Useful flags on start: `--sync yes|no|ask`, `--workspace <id>`, `--agent <name>`,
`--agent-version <v>`, `--model <model>`.

## Phases

```bash
myrqen phase start <phase>
myrqen phase complete <phase>
```

`preflight`, `scope`, `discovery`, `source_review`, `runtime_validation`,
`access_control`, `validation`, `reporting`.

## Scope and safety gates

```bash
myrqen target authorize <url> [--grant]
myrqen target check <url>
myrqen target redirect <from> <to>
myrqen action check --intent <intent> [--description <text>] [--method <method>] \
                   [--target <target>] [--repeat <count>] [--disposable]
```

Exit code 3 means out of scope or not authorized. Exit code 4 means the action is
prohibited.

## Findings, notes, metrics

```bash
echo '<json>' | myrqen finding submit
myrqen finding submit --file finding.json
myrqen finding verify <findingId> --description "<what was requested and what came back>" [--kind runtime|identity_differential|configuration|other] [--location "<route or file>"]
myrqen finding refute <findingId> --reason "<what was tried and what happened instead>"
myrqen session static-pass
myrqen note coverage "<text>" [--area "<area>"]
myrqen note limitation "<text>" [--area "<area>"]
myrqen metrics token --source <exact|estimated|unavailable> [--count <n>] [--estimator <name>]
```

Exit code 2 means the finding was rejected; the output explains why.

## Fix workflow

```bash
myrqen fix prompt <findingId>
myrqen fix record <findingId> --applied [--files a,b] [--note "<text>"]
myrqen fix record <findingId> --verified
myrqen fix record <findingId> --verification-failed
myrqen fix record <findingId> --reverted
```

## Account, project, and platform

```bash
myrqen link                 # install the skill and link this device
myrqen install              # install or update the skill only
myrqen status               # account, device, and quota state
myrqen logout               # remove the local credential
myrqen workspace [--set <id>] [--detach]
myrqen reports
myrqen sync <localReportId>
myrqen doctor
myrqen update [--apply] [--pin <version>] [--unpin] [--channel <channel>]
myrqen config set-url <url>
```
