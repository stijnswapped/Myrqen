import { Command, Option } from "commander";
import { BRAND, CLI_VERSION } from "@myrqen/brand";
import type { EffortRequested, ScanPhase, TokenSource } from "@myrqen/contracts";
import { EFFORT_REQUESTED_VALUES, SCAN_PHASES } from "@myrqen/contracts";
import { findRepoRoot } from "./discovery/project.js";
import { blank, fail, json, write } from "./ui/output.js";
import { isInteractive } from "./ui/prompt.js";
import { requireSession, saveSession } from "./session/state.js";
import { createCloudShell, startSession } from "./session/start.js";
import { finishSession } from "./session/finish.js";
import { resolveClient } from "./api/client.js";
import {
  authorizeTarget,
  checkAction,
  checkRedirect,
  checkTargetInScope,
  printFixAllPrompt,
  printFixPrompt,
  recordAgentMetadata,
  recordFix,
  recordNote,
  recordTokenUsage,
  submitFinding,
  verifyFinding,
  refuteFinding,
  updatePhase
} from "./agent/protocol.js";
import { accountLinkCommand } from "./commands/link.js";
import { integrationStatus, linkIntegrations, unlinkIntegrations } from "./commands/integrations.js";
import { doctorCommand } from "./commands/doctor.js";
import { reportsCommand, syncCommand } from "./commands/reports.js";
import { baselineCommand } from "./commands/baseline.js";
import { workspaceCommand } from "./commands/workspace.js";
import { updateCommand } from "./commands/update.js";
import {
  logoutCommand,
  setTelemetryCommand,
  setUrlCommand,
  statusCommand as accountStatusCommand
} from "./commands/account.js";
import { skillSourceDirectory } from "./install/skill.js";
import { configUsage, projectConfigCommand } from "./commands/config.js";
import { diffCommand, reportCommand } from "./commands/report.js";
import { watchCommand } from "./commands/watch.js";
import { EXIT_NEEDS_EVIDENCE, EXIT_RETEST_FAILED, fixCommand, retestCommand } from "./commands/fix.js";
import type { RunConfigFlags } from "./session/run-config.js";
import { runStaticPass } from "./scan/static-pass.js";

async function readStdin(): Promise<string> {
  if (process.stdin.isTTY) return "";
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString("utf8");
}

async function currentSession(sessionId?: string) {
  const repoRoot = await findRepoRoot(process.cwd());
  return requireSession(repoRoot, sessionId);
}

const program = new Command();
program
  .name(BRAND.cliName)
  .description(`${BRAND.displayName}: authorized, local-first application security assessment run by your coding agent`)
  .version(CLI_VERSION)
  .option("--json", "emit machine-readable JSON for agent consumption")
  .option("--session <id>", "act on a specific local report id instead of the current session");

function globalOptions(): { asJson: boolean; sessionId?: string } {
  const options = program.opts<{ json?: boolean; session?: string }>();
  return { asJson: Boolean(options.json), ...(options.session ? { sessionId: options.session } : {}) };
}

interface RunFlagOptions {
  startCommand?: string;
  appUrl?: string;
  appEnv?: string[];
}

/** The app-under-test flags shared by every way of starting a session. */
function withRunFlags(command: Command): Command {
  return command
    .option("--start-command <command>", "how to start the app under test; saved to the project config")
    .option("--app-url <port-or-url>", "loopback port or URL the app answers on; saved to the project config")
    .option("--app-env <names>", "environment variable NAMES the app needs (comma-separated, repeatable); never values", collect, []);
}

function runFlags(options: RunFlagOptions): { runConfig?: RunConfigFlags } {
  const flags: RunConfigFlags = {
    ...(options.startCommand ? { startCommand: options.startCommand } : {}),
    ...(options.appUrl ? { appUrl: options.appUrl } : {}),
    ...(options.appEnv && options.appEnv.length > 0 ? { env: options.appEnv } : {})
  };
  return Object.keys(flags).length > 0 ? { runConfig: flags } : {};
}

/* ---------- effort shortcuts ---------- */

for (const effort of EFFORT_REQUESTED_VALUES) {
  withRunFlags(
    program
      .command(effort)
      .description(`Start a ${effort} assessment in the current project`)
      .option("--sync <mode>", "yes, no, or ask (default ask)")
      .option("--workspace <id>", "bind this repository to an explicit workspace")
      .option("--agent <name>", "host agent name")
      .option("--agent-version <version>", "host agent version")
      .option("--model <model>", "host model identifier when the agent can report it")
  ).action(
    async (options: { sync?: string; workspace?: string; agent?: string; agentVersion?: string; model?: string } & RunFlagOptions) => {
      const { asJson } = globalOptions();
      await startSession({
        effort: effort as EffortRequested,
        asJson,
        ...runFlags(options),
        ...(options.sync ? { sync: options.sync as "yes" | "no" | "ask" } : {}),
        ...(options.workspace ? { workspaceId: options.workspace } : {}),
        ...(options.agent ? { agentName: options.agent } : {}),
        ...(options.agentVersion ? { agentVersion: options.agentVersion } : {}),
        ...(options.model ? { agentModel: options.model } : {})
      });
    }
  );
}

/* ---------- session lifecycle ---------- */

const session = program.command("session").description("Manage the local assessment session");

withRunFlags(session
  .command("start")
  .description("Start a session and print the context the host agent must work inside"))
  .addOption(new Option("--effort <effort>", "low, high, xhigh, ultra, or auto").default("auto"))
  .option("--sync <mode>", "yes, no, or ask (default ask)")
  .option("--workspace <id>", "bind this repository to an explicit workspace")
  .option("--agent <name>", "host agent name")
  .option("--agent-version <version>", "host agent version")
  .option("--model <model>", "host model identifier when the agent can report it")
  .action(async (options: { effort: string; sync?: string; workspace?: string; agent?: string; agentVersion?: string; model?: string } & RunFlagOptions) => {
    const { asJson } = globalOptions();
    if (!EFFORT_REQUESTED_VALUES.includes(options.effort as EffortRequested)) {
      throw new Error(`Unknown effort "${options.effort}". Use one of: ${EFFORT_REQUESTED_VALUES.join(", ")}.`);
    }
    await startSession({
      effort: options.effort as EffortRequested,
      asJson,
      ...runFlags(options),
      ...(options.sync ? { sync: options.sync as "yes" | "no" | "ask" } : {}),
      ...(options.workspace ? { workspaceId: options.workspace } : {}),
      ...(options.agent ? { agentName: options.agent } : {}),
      ...(options.agentVersion ? { agentVersion: options.agentVersion } : {}),
      ...(options.model ? { agentModel: options.model } : {})
    });
  });

session
  .command("context")
  .description("Print the current session context")
  .action(async () => {
    const { asJson, sessionId } = globalOptions();
    const state = await currentSession(sessionId);
    if (asJson) json(state);
    else {
      write(`Local report ${state.localReportId}`);
      write(`State ${state.state} · effort ${state.effort.resolved} · cloud ${state.cloud.state}`);
      write(`Findings ${state.findings.length} · candidates ${state.candidateCount} · duplicates ${state.duplicateCount}`);
      if (state.cloud.reportUrl) write(`Live report ${state.cloud.reportUrl}`);
    }
  });

session
  .command("sync-decision <answer>")
  .description("Record the user's answer to the sync question for this scan")
  .action(async (answer: string) => {
    const { asJson, sessionId } = globalOptions();
    const state = await currentSession(sessionId);
    const wants = /^(y|yes|true)$/i.test(answer);

    if (state.cloud.state === "live" || state.cloud.state === "synced") {
      if (asJson) json({ cloud: state.cloud });
      else write(`This scan is already syncing: ${state.cloud.reportUrl}`);
      return;
    }
    if (state.cloud.state === "quota_blocked") {
      if (asJson) json({ cloud: state.cloud });
      else write(state.cloud.reason ?? "Cloud report limit reached. This scan stays local.");
      return;
    }

    if (!wants) {
      state.cloud.state = "not_requested";
      state.cloud.reason = "Sync was declined for this scan.";
      await saveSession(state);
      if (asJson) json({ cloud: state.cloud });
      else write("This scan will stay local. No cloud events are emitted.");
      return;
    }

    const { client } = await resolveClient();
    if (!client.authenticated) throw new Error(`This device is not linked. Run "${BRAND.cliName} link" first.`);
    await createCloudShell(state, client);
    await saveSession(state);
    if (asJson) json({ cloud: state.cloud });
    else if (state.cloud.reportUrl) write(`Live report ${state.cloud.reportUrl}`);
    else write(state.cloud.reason ?? "The cloud report could not be created.");
  });

session
  .command("agent")
  .description("Record host agent and model metadata")
  .option("--name <name>")
  .option("--agent-version <version>")
  .option("--model <model>")
  .action(async (options: { name?: string; agentVersion?: string; model?: string }) => {
    const { asJson, sessionId } = globalOptions();
    const state = await currentSession(sessionId);
    await recordAgentMetadata(
      state,
      {
        ...(options.name ? { name: options.name } : {}),
        ...(options.agentVersion ? { version: options.agentVersion } : {}),
        ...(options.model ? { model: options.model } : {})
      },
      { asJson }
    );
  });

session
  .command("static-pass")
  .description("Re-run the built-in static analysis pass and submit its candidates")
  .action(async () => {
    const { asJson, sessionId } = globalOptions();
    const state = await currentSession(sessionId);
    const result = await runStaticPass(state, { asJson });
    if (asJson) json(result);
  });

session
  .command("finish")
  .description("Validate findings, write local report formats, and sync if this scan opted in")
  .action(async () => {
    const { asJson, sessionId } = globalOptions();
    const state = await currentSession(sessionId);
    await finishSession({ state, asJson });
  });

session
  .command("cancel")
  .description("Finish early and keep whatever was validated so far")
  .action(async () => {
    const { asJson, sessionId } = globalOptions();
    const state = await currentSession(sessionId);
    await finishSession({ state, asJson, cancelled: true });
  });

/* ---------- phases ---------- */

const phase = program.command("phase").description("Record assessment phase transitions");

function parsePhase(value: string): ScanPhase {
  if (!SCAN_PHASES.includes(value as ScanPhase)) {
    throw new Error(`Unknown phase "${value}". Use one of: ${SCAN_PHASES.join(", ")}.`);
  }
  return value as ScanPhase;
}

phase
  .command("start <phase>")
  .description("Mark a phase as running")
  .action(async (value: string) => {
    const { asJson, sessionId } = globalOptions();
    const state = await currentSession(sessionId);
    await updatePhase(state, parsePhase(value), "running", { asJson });
  });

phase
  .command("complete <phase>")
  .description("Mark a phase as complete")
  .action(async (value: string) => {
    const { asJson, sessionId } = globalOptions();
    const state = await currentSession(sessionId);
    await updatePhase(state, parsePhase(value), "complete", { asJson });
  });

/* ---------- scope and safety gates ---------- */

const target = program.command("target").description("Authorization gates for dynamic testing");

target
  .command("authorize <url>")
  .description("Authorize one exact external origin after explicit user confirmation")
  .option("--grant", "the user has explicitly confirmed authorization for this exact origin")
  .action(async (url: string, options: { grant?: boolean }) => {
    const { asJson, sessionId } = globalOptions();
    const state = await currentSession(sessionId);
    const decision = await authorizeTarget(state, url, { asJson, ...(options.grant ? { grant: true } : {}) });
    if (decision.decision === "denied") process.exitCode = 3;
  });

target
  .command("check <url>")
  .description("Check whether a target is already in scope")
  .action(async (url: string) => {
    const { asJson, sessionId } = globalOptions();
    const state = await currentSession(sessionId);
    if (!(await checkTargetInScope(state, url, { asJson }))) process.exitCode = 3;
  });

target
  .command("redirect <from> <to>")
  .description("Decide whether a redirect may be followed")
  .action(async (from: string, to: string) => {
    const { asJson, sessionId } = globalOptions();
    const state = await currentSession(sessionId);
    if (!checkRedirect(state, from, to, { asJson })) process.exitCode = 3;
  });

program
  .command("action")
  .description("Check a planned action against the safety policy")
  .argument("<subcommand>", "check")
  .option("--intent <intent>", "short machine-readable intent")
  .option("--description <text>")
  .option("--method <method>")
  .option("--target <target>")
  .option("--repeat <count>", "number of repeated operations")
  .option("--disposable", "the target is a local disposable fixture")
  .action(async (subcommand: string, options: { intent?: string; description?: string; method?: string; target?: string; repeat?: string; disposable?: boolean }) => {
    if (subcommand !== "check") throw new Error('The only supported subcommand is "check".');
    if (!options.intent) throw new Error("--intent is required.");
    const { asJson, sessionId } = globalOptions();
    const state = await currentSession(sessionId);
    const allowed = await checkAction(
      state,
      {
        intent: options.intent,
        ...(options.description ? { description: options.description } : {}),
        ...(options.method ? { method: options.method } : {}),
        ...(options.target ? { target: options.target } : {}),
        ...(options.repeat ? { repeatCount: Number(options.repeat) } : {}),
        ...(options.disposable ? { localDisposableFixture: true } : {})
      },
      { asJson }
    );
    if (!allowed) process.exitCode = 4;
  });

/* ---------- findings and notes ---------- */

const finding = program
  .command("finding")
  .description("Submit, verify, or refute findings in the current session");

finding
  .command("verify <findingId>")
  .description("Attach runtime evidence to a finding and mark it verified")
  .requiredOption("--description <text>", "what was requested and what came back")
  .option("--kind <kind>", "evidence kind: runtime, identity_differential, configuration, or other", "runtime")
  .option("--location <where>", "the route or file the observation belongs to")
  .action(async (findingId: string, options: { description: string; kind: string; location?: string }) => {
    const { asJson, sessionId } = globalOptions();
    const state = await currentSession(sessionId);
    await verifyFinding(
      state,
      findingId,
      {
        kind: options.kind,
        description: options.description,
        ...(options.location ? { location: options.location } : {})
      },
      { asJson }
    );
  });

finding
  .command("refute <findingId>")
  .description("Record that a candidate could not be reproduced, with the reason")
  .requiredOption("--reason <text>", "what was tried and what happened instead")
  .action(async (findingId: string, options: { reason: string }) => {
    const { asJson, sessionId } = globalOptions();
    const state = await currentSession(sessionId);
    await refuteFinding(state, findingId, options.reason, { asJson });
  });


/*
 * The command the methodology already told the agent to use.
 *
 * `references/METHODOLOGY.md` opens its source-review phase with "start by reading
 * its candidates rather than the file tree. Each one names a route, a line, and the
 * data flow it believes in." Nothing returned them. `SessionContext.staticPass`
 * carried `candidatesRecorded` — a count — and `session static-pass` *re-runs* the
 * pass and resubmits everything, which inflates the duplicate counter and still
 * prints numbers. An agent following the skill literally settled nothing, because it
 * could not see what there was to settle.
 *
 * Ordered worst-first: unsettled before settled, then by severity. What an agent
 * needs first is the candidate nobody has exercised.
 */
finding
  .command("list")
  .description("List the candidates and findings in the current session, unsettled first")
  .option("--all", "include findings already verified or refuted")
  .action(async (options: { all?: boolean }) => {
    const { asJson, sessionId } = globalOptions();
    const state = await currentSession(sessionId);

    const RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
    const settled = (finding: (typeof state.findings)[number]): boolean =>
      finding.verification === "verified" || finding.status === "false_positive";

    const rows = [...state.findings]
      .filter((finding) => options.all === true || !settled(finding))
      .sort(
        (left, right) =>
          Number(settled(left)) - Number(settled(right)) ||
          (RANK[left.severity] ?? 9) - (RANK[right.severity] ?? 9) ||
          left.id.localeCompare(right.id)
      );

    if (asJson) {
      json({
        localReportId: state.localReportId,
        total: state.findings.length,
        listed: rows.length,
        findings: rows
      });
      return;
    }

    if (rows.length === 0) {
      write(
        state.findings.length === 0
          ? "No candidates in this session. If the static pass ran and found nothing, say so in the report rather than treating it as a clean bill of health."
          : "Every finding in this session is settled. Use --all to see them."
      );
      return;
    }

    write(`${rows.length} of ${state.findings.length} finding(s), unsettled first:`);
    for (const finding of rows) {
      const where = finding.affected.route ?? finding.affected.component ?? finding.affected.origin ?? "no route resolved";
      write("");
      write(`${finding.id}  ${finding.severity.toUpperCase()}  ${finding.verification}${settled(finding) ? `  [${finding.status}]` : ""}`);
      write(`  ${finding.category} · ${where}`);
      write(`  ${finding.title}`);
      if (finding.reproduction) write(`  how to exercise it: ${finding.reproduction}`);
    }
    write("");
    write("Settle each one with `myrqen finding verify <id> --description \"<what you observed>\"` or `myrqen finding refute <id> --reason \"<why>\"`.");
  });

finding
  .command("submit")
  .description("Submit a structured finding (JSON on stdin)")
  .option("--file <path>", "read the finding from a file instead of stdin")
  .action(async (options: { file?: string }) => {
    const { asJson, sessionId } = globalOptions();
    const state = await currentSession(sessionId);
    const raw = options.file ? await (await import("node:fs/promises")).readFile(options.file, "utf8") : await readStdin();
    if (raw.trim().length === 0) {
      throw new Error("No finding was provided. Pipe JSON on stdin or pass --file.");
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (error) {
      throw new Error(`The finding is not valid JSON: ${error instanceof Error ? error.message : "parse error"}`);
    }
    const result = await submitFinding(state, parsed, { asJson });
    if (!result.accepted) process.exitCode = 2;
  });

const note = program.command("note").description("Record honest coverage and limitations");

note
  .command("coverage <text>")
  .description("Record something that was assessed")
  .option("--area <area>", "name the coverage area")
  .action(async (text: string, options: { area?: string }) => {
    const { asJson, sessionId } = globalOptions();
    const state = await currentSession(sessionId);
    await recordNote(state, "coverage", text, { asJson, ...(options.area ? { area: options.area } : {}) });
  });

note
  .command("limitation <text>")
  .description("Record something that was not or could not be assessed")
  .option("--area <area>", "name the area that was not assessed")
  .action(async (text: string, options: { area?: string }) => {
    const { asJson, sessionId } = globalOptions();
    const state = await currentSession(sessionId);
    await recordNote(state, "limitation", text, { asJson, ...(options.area ? { area: options.area } : {}) });
  });

program
  .command("metrics")
  .description("Record scan metrics")
  .argument("<subcommand>", "token")
  .requiredOption("--source <source>", "exact, estimated, or unavailable")
  .option("--count <count>", "token count")
  .option("--estimator <name>", "estimator name and version for estimated counts")
  .action(async (subcommand: string, options: { source: string; count?: string; estimator?: string }) => {
    if (subcommand !== "token") throw new Error('The only supported subcommand is "token".');
    const { asJson, sessionId } = globalOptions();
    const state = await currentSession(sessionId);
    if (!["exact", "estimated", "unavailable"].includes(options.source)) {
      throw new Error("--source must be exact, estimated, or unavailable.");
    }
    await recordTokenUsage(
      state,
      options.source as TokenSource,
      options.count === undefined ? undefined : Number(options.count),
      options.estimator,
      { asJson }
    );
  });

/* ---------- fix workflow ---------- */

const fix = program
  .command("fix")
  .description("Fix one finding on its own branch (fix <findingId>), or print prompts and record outcomes");

fix
  .command("start <findingId>", { isDefault: true })
  .description("Refuse a dirty tree, branch myrqen/fix-<id> from HEAD, then apply a mechanical fix or write the agent's plan")
  .action(async (findingId: string) => {
    const { asJson, sessionId } = globalOptions();
    const state = await currentSession(sessionId);
    await fixCommand(state, findingId, { asJson });
  });

fix
  .command("prompt [findingId]")
  .description("Print a remediation prompt for a coding agent, or --all for the whole report")
  .option("--all", "one prompt covering every open finding, ordered by file")
  .action(async (findingId: string | undefined, options: { all?: boolean }) => {
    const { sessionId } = globalOptions();
    const state = await currentSession(sessionId);

    // `--all` is the shape people reach for: fix what you found. Each finding is still
    // marked `fix_suggested` individually, so the report distinguishes "a prompt was
    // produced for this" from "somebody fixed this" exactly as the single-finding path
    // does.
    if (options.all) {
      printFixAllPrompt(state);
      const open = state.findings.filter(
        (finding) => !["fixed_verified", "false_positive", "accepted_risk"].includes(finding.status ?? "open")
      );
      for (const finding of open) {
        await recordFix(state, finding.id, "suggested", { asJson: false }).catch(() => undefined);
      }
      return;
    }

    if (!findingId) {
      throw new Error("Give a finding id, or --all for every open finding.");
    }
    printFixPrompt(state, findingId);
    await recordFix(state, findingId, "suggested", { asJson: false }).catch(() => undefined);
  });

fix
  .command("record <findingId>")
  .description("Record the outcome of an applied fix")
  .option("--applied", "a code change was applied")
  .option("--verified", "the targeted security verification passed")
  .option("--verification-failed", "the targeted security verification did not pass")
  .option("--reverted", "the change was reverted")
  .option("--files <files>", "comma-separated changed files")
  .option("--note <note>")
  .action(async (findingId: string, options: { applied?: boolean; verified?: boolean; verificationFailed?: boolean; reverted?: boolean; files?: string; note?: string }) => {
    const { asJson, sessionId } = globalOptions();
    const state = await currentSession(sessionId);
    const action = options.verified
      ? "verified"
      : options.verificationFailed
        ? "verification_failed"
        : options.reverted
          ? "reverted"
          : options.applied
            ? "applied"
            : null;
    if (!action) {
      throw new Error("Choose one of --applied, --verified, --verification-failed, or --reverted.");
    }
    await recordFix(state, findingId, action, {
      asJson,
      ...(options.files ? { changedFiles: options.files.split(",").map((file) => file.trim()).filter(Boolean) } : {}),
      ...(options.note ? { note: options.note } : {})
    });
  });

program
  .command("retest <findingId>")
  .description("Re-run only this finding's check; on a pass, commit on its fix branch and mark it fixed and verified")
  .option("--evidence <text>", "what the original request returned when repeated after the fix (runtime-verified findings)")
  .option("--still-reproduces", "the repeated request still showed the issue")
  .option("--no-commit", "record the result but do not commit")
  .action(async (findingId: string, options: { evidence?: string; stillReproduces?: boolean; commit?: boolean }) => {
    const { asJson, sessionId } = globalOptions();
    const state = await currentSession(sessionId);
    const outcome = await retestCommand(state, findingId, {
      asJson,
      ...(options.evidence ? { evidence: options.evidence } : {}),
      ...(options.stillReproduces ? { stillReproduces: true } : {}),
      ...(options.commit === false ? { commit: false } : {})
    });
    if (outcome.outcome === "fail") process.exitCode = EXIT_RETEST_FAILED;
    if (outcome.outcome === "needs_runtime_evidence") process.exitCode = EXIT_NEEDS_EVIDENCE;
  });

/* ---------- account, project, and platform ---------- */

/**
 * Setup.
 *
 * `link` is the one command a new user has to remember, so it does the whole
 * job: detect the coding agents on this machine, let the user choose where
 * Myrqen should integrate, show exactly which files change, write them, and then
 * offer to connect an account for cloud reports. Account linking is offered
 * last and is entirely optional — scanning works without it, and a setup command
 * that demands a login before it does anything useful is a setup command people
 * abandon.
 */
function setupOptions(options: {
  agent?: string[];
  all?: boolean;
  scope?: string;
  dryRun?: boolean;
  yes?: boolean;
  verbose?: boolean;
  probe?: boolean;
}) {
  if (options.scope && !["project", "global", "both"].includes(options.scope)) {
    throw new Error(`--scope must be project, global, or both.`);
  }
  return {
    asJson: globalOptions().asJson,
    ...(options.agent && options.agent.length > 0 ? { agents: options.agent } : {}),
    ...(options.all ? { all: true } : {}),
    ...(options.scope ? { scope: options.scope as "project" | "global" | "both" } : {}),
    ...(options.dryRun ? { dryRun: true } : {}),
    ...(options.yes ? { yes: true } : {}),
    ...(options.verbose ? { verbose: true } : {}),
    // Commander turns `--no-probe` into `probe: false`. Anything else means the
    // user did not ask, and the default is decided from the environment.
    ...(options.probe === false ? { noProbe: true } : {})
  };
}

function collect(value: string, previous: string[]): string[] {
  return [...previous, value];
}

program
  .command("link")
  .description("Detect your coding agents, configure them, and optionally connect an account")
  .option("--agent <id>", "install for one agent; repeatable", collect, [])
  .option("--all", "install for every detected agent without asking")
  .option("--scope <scope>", "project, global, or both")
  .option("--dry-run", "show the plan and write nothing")
  .option("-y, --yes", "accept the plan without a confirmation prompt")
  .option("--verbose", "print every file in the plan instead of collapsing bundles")
  .option("--no-probe", "detect from files alone; never execute an agent's own CLI")
  .option("--account", "also connect an account for cloud reports")
  .option("--no-account", "skip the account step entirely")
  .option("--url <url>", "app base URL for the account step")
  .option("--device-name <name>", "name for this device in the account")
  .option("--no-open", "do not open a browser automatically")
  .action(
    async (options: {
      agent?: string[];
      all?: boolean;
      scope?: string;
      dryRun?: boolean;
      yes?: boolean;
      verbose?: boolean;
      probe?: boolean;
      account?: boolean;
      url?: string;
      deviceName?: string;
      open?: boolean;
    }) => {
      const { asJson } = globalOptions();
      await linkIntegrations(setupOptions(options));
      // The account step is a question, so it is only asked where a question can
      // be answered. Reaching it in a scripted run made `link --all --yes`
      // install everything correctly and then exit non-zero, because the prompt
      // saw end-of-input and read it as a refusal.
      if (asJson || options.dryRun || options.account === false) return;
      if (options.account !== true && (!isInteractive() || options.yes)) return;
      await accountLinkCommand({
        offer: options.account !== true,
        ...(options.url ? { apiBaseUrl: options.url } : {}),
        ...(options.deviceName ? { deviceName: options.deviceName } : {}),
        ...(options.open === false ? { open: false } : {})
      });
    }
  );

program
  .command("login")
  .description("Connect this device to an account, without touching agent integrations")
  .option("--url <url>", "app base URL")
  .option("--device-name <name>")
  .option("--no-open", "do not open a browser automatically")
  .action(async (options: { url?: string; deviceName?: string; open?: boolean }) =>
    accountLinkCommand({
      ...(options.url ? { apiBaseUrl: options.url } : {}),
      ...(options.deviceName ? { deviceName: options.deviceName } : {}),
      ...(options.open === false ? { open: false } : {})
    })
  );

program
  .command("install")
  .description("Alias for link, without the account step")
  .option("--agent <id>", "install for one agent; repeatable", collect, [])
  .option("--all", "install for every detected agent without asking")
  .option("--scope <scope>", "project, global, or both")
  .option("--dry-run", "show the plan and write nothing")
  .option("-y, --yes", "accept the plan without a confirmation prompt")
  .option("--no-probe", "detect from files alone; never execute an agent's own CLI")
  .action(
    async (options: {
      agent?: string[];
      all?: boolean;
      scope?: string;
      dryRun?: boolean;
      yes?: boolean;
      probe?: boolean;
    }) => {
      await linkIntegrations(setupOptions(options));
    }
  );

program
  .command("unlink")
  .description(`Remove ${BRAND.displayName} integrations, leaving your own instructions untouched`)
  .option("--agent <id>", "remove one agent's integration; repeatable", collect, [])
  .option("--all", `remove every ${BRAND.displayName} integration found`)
  .option("--scope <scope>", "limit the removal to project or global")
  .option("--dry-run", "show what would be removed and remove nothing")
  .option("-y, --yes", "remove without a confirmation prompt")
  .action(async (options: { agent?: string[]; all?: boolean; scope?: string; dryRun?: boolean; yes?: boolean }) => {
    if (options.scope && options.scope !== "project" && options.scope !== "global") {
      throw new Error("--scope must be project or global.");
    }
    await unlinkIntegrations({
      asJson: globalOptions().asJson,
      ...(options.agent && options.agent.length > 0 ? { agents: options.agent } : {}),
      ...(options.all ? { all: true } : {}),
      ...(options.scope ? { scope: options.scope as "project" | "global" } : {}),
      ...(options.dryRun ? { dryRun: true } : {}),
      ...(options.yes ? { yes: true } : {})
    });
  });

program
  .command("status")
  .description("Show which agents are linked here, plus account and quota state")
  .option("--account", "show only the account, device, and quota state")
  .option("--agents", "show only the agent integrations")
  .option("--no-probe", "detect from files alone; never execute an agent's own CLI")
  .action(async (options: { account?: boolean; agents?: boolean; probe?: boolean }) => {
    const { asJson } = globalOptions();
    const both = !options.account && !options.agents;
    const noProbe = options.probe === false ? { noProbe: true } : {};
    // One command, one JSON document. Two `json()` calls concatenate two
    // objects on stdout and `JSON.parse` fails on the result.
    if (asJson && both) {
      const integrations = await integrationStatus({ collect: true, ...noProbe });
      const account = await accountStatusCommand({ collect: true });
      json({ ...(integrations ?? {}), account });
      return;
    }
    if (both || options.agents) await integrationStatus({ asJson, ...noProbe });
    if (both || options.account) {
      if (both && !asJson) blank();
      await accountStatusCommand({ asJson });
    }
  });

program.command("logout").description("Remove the local device credential").action(async () => logoutCommand());

program
  .command("config")
  .description("Show or change this project's run settings (start command, app URL, env names) and local settings")
  .argument("[subcommand]", "show | detect | set <key> <value> | trust | reset | set-url <url> | telemetry <on|off>")
  .argument("[values...]")
  .action(async (subcommand: string | undefined, values: string[]) => {
    const value = values[0];
    if (subcommand === "set-url" && value) return setUrlCommand(value);
    if (subcommand === "telemetry" && value) return setTelemetryCommand(value);
    if (await projectConfigCommand(subcommand, values, { asJson: globalOptions().asJson })) return;
    throw new Error(configUsage());
  });

program
  .command("workspace")
  .description("Show or change the workspace binding for this repository")
  .option("--set <workspaceId>", "bind this repository to a workspace")
  .option("--detach", "remove the current binding")
  .action(async (options: { set?: string; detach?: boolean }) => {
    await workspaceCommand({
      asJson: globalOptions().asJson,
      ...(options.set ? { set: options.set } : {}),
      ...(options.detach ? { detach: true } : {})
    });
  });

program
  .command("reports")
  .description("List local reports and their cloud state")
  .action(async () => reportsCommand({ asJson: globalOptions().asJson }));

program
  .command("baseline")
  .description("Record a finished report's findings in .myrqen/baseline.json, a file meant to be committed")
  .option("--from <localReportId>", "take the baseline from this local report instead of the newest one")
  .action(async (options: { from?: string }) =>
    baselineCommand({ asJson: globalOptions().asJson, ...(options.from ? { from: options.from } : {}) })
  );

program
  .command("report [run]")
  .description("Open the latest local HTML report, print one format's path, or list recent runs")
  .option("--format <format>", "html, md, json, or sarif: print that file's path instead of opening")
  .option("--list", "list recent runs with their counts")
  .option("--last <n>", "list the last n runs")
  .option("--no-open", "print the path instead of opening a browser")
  .action(async (run: string | undefined, options: { format?: string; list?: boolean; last?: string; open?: boolean }) => {
    await reportCommand(run, {
      asJson: globalOptions().asJson,
      ...(options.format ? { format: options.format } : {}),
      ...(options.list ? { list: true } : {}),
      ...(options.last !== undefined ? { last: Number(options.last) } : {}),
      ...(options.open === false ? { open: false } : {})
    });
  });

program
  .command("diff [base] [head]")
  .description("Compare two runs by stable fingerprint: new, fixed, regressed, still open (default: the last two)")
  .action(async (base: string | undefined, head: string | undefined) => {
    await diffCommand(base, head, { asJson: globalOptions().asJson });
  });

program
  .command("watch")
  .description("Follow the current session live from another terminal while your agent runs it")
  .option("--once", "print the current progress once and exit")
  .action(async (options: { once?: boolean }) => {
    const { asJson, sessionId } = globalOptions();
    await watchCommand({ ...(asJson ? { asJson } : {}), ...(options.once ? { once: true } : {}), ...(sessionId ? { sessionId } : {}) });
  });

program
  .command("sync <localReportId>")
  .description("Sync an existing local report after rechecking login, device, and quota")
  .action(async (localReportId: string) => syncCommand(localReportId, { asJson: globalOptions().asJson }));

program
  .command("doctor")
  .description("Report what this machine and agent setup can assess")
  .option("--no-probe", "detect from files alone; never execute an agent's own CLI")
  .action(async (options: { probe?: boolean }) => {
    await doctorCommand({
      asJson: globalOptions().asJson,
      ...(options.probe === false ? { noProbe: true } : {})
    });
  });

program
  .command("update")
  .description("Verify and stage a signed update")
  .option("--apply", "download and verify the artifact")
  .option("--pin <version>", "pin this machine to a version")
  .option("--unpin", "remove the version pin")
  .option("--channel <channel>", "stable, beta, or canary")
  .action(async (options: { apply?: boolean; pin?: string; unpin?: boolean; channel?: string }) => {
    await updateCommand({
      asJson: globalOptions().asJson,
      ...(options.apply ? { apply: true } : {}),
      ...(options.pin ? { pin: options.pin } : {}),
      ...(options.unpin ? { unpin: true } : {}),
      ...(options.channel ? { channel: options.channel as "stable" | "beta" | "canary" } : {})
    });
  });

program
  .command("skill")
  .description("Show where the portable agent skill bundle lives")
  .argument("[subcommand]", "path")
  .action(async () => {
    write(await skillSourceDirectory());
  });

/**
 * `myrqen` with no arguments.
 *
 * A usage wall is the wrong answer to somebody who has just run `npx myrqen`
 * for the first time and does not yet know what the tool is. Setup is, and
 * `--help` is one word away for anybody who wants the list.
 */
if (process.argv.length <= 2) {
  process.argv.push("link");
}

program.parseAsync(process.argv).catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  // A machine consumer parses stdout. Prose on stderr and an empty stdout gives
  // it "Unexpected end of JSON input" instead of the reason it needed.
  if (program.opts<{ json?: boolean }>().json) json({ error: { code: "COMMAND_FAILED", message } });
  else fail(message);
  if (process.env.MYRQEN_DEBUG === "1" && error instanceof Error && error.stack) {
    process.stderr.write(`${error.stack}\n`);
  }
  process.exitCode = 1;
});
