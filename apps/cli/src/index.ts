import { Command, Option } from "commander";
import { BRAND, CLI_VERSION } from "@myrqen/brand";
import type { EffortRequested, ScanPhase, TokenSource } from "@myrqen/contracts";
import { EFFORT_REQUESTED_VALUES, SCAN_PHASES } from "@myrqen/contracts";
import { findRepoRoot } from "./discovery/project.js";
import { fail, json, write } from "./ui/output.js";
import { requireSession, saveSession } from "./session/state.js";
import { createCloudShell, startSession } from "./session/start.js";
import { finishSession } from "./session/finish.js";
import { resolveClient } from "./api/client.js";
import {
  authorizeTarget,
  checkAction,
  checkRedirect,
  checkTargetInScope,
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
import { installCommand, linkCommand } from "./commands/link.js";
import { doctorCommand } from "./commands/doctor.js";
import { reportsCommand, syncCommand } from "./commands/reports.js";
import { workspaceCommand } from "./commands/workspace.js";
import { updateCommand } from "./commands/update.js";
import { logoutCommand, setUrlCommand, statusCommand } from "./commands/account.js";
import { skillSourceDirectory } from "./install/skill.js";
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

/* ---------- effort shortcuts ---------- */

for (const effort of EFFORT_REQUESTED_VALUES) {
  program
    .command(effort)
    .description(`Start a ${effort} assessment in the current project`)
    .option("--sync <mode>", "yes, no, or ask (default ask)")
    .option("--workspace <id>", "bind this repository to an explicit workspace")
    .option("--agent <name>", "host agent name")
    .option("--agent-version <version>", "host agent version")
    .option("--model <model>", "host model identifier when the agent can report it")
    .action(async (options: { sync?: string; workspace?: string; agent?: string; agentVersion?: string; model?: string }) => {
      const { asJson } = globalOptions();
      await startSession({
        effort: effort as EffortRequested,
        asJson,
        ...(options.sync ? { sync: options.sync as "yes" | "no" | "ask" } : {}),
        ...(options.workspace ? { workspaceId: options.workspace } : {}),
        ...(options.agent ? { agentName: options.agent } : {}),
        ...(options.agentVersion ? { agentVersion: options.agentVersion } : {}),
        ...(options.model ? { agentModel: options.model } : {})
      });
    });
}

/* ---------- session lifecycle ---------- */

const session = program.command("session").description("Manage the local assessment session");

session
  .command("start")
  .description("Start a session and print the context the host agent must work inside")
  .addOption(new Option("--effort <effort>", "low, high, xhigh, ultra, or auto").default("auto"))
  .option("--sync <mode>", "yes, no, or ask (default ask)")
  .option("--workspace <id>", "bind this repository to an explicit workspace")
  .option("--agent <name>", "host agent name")
  .option("--agent-version <version>", "host agent version")
  .option("--model <model>", "host model identifier when the agent can report it")
  .action(async (options: { effort: string; sync?: string; workspace?: string; agent?: string; agentVersion?: string; model?: string }) => {
    const { asJson } = globalOptions();
    if (!EFFORT_REQUESTED_VALUES.includes(options.effort as EffortRequested)) {
      throw new Error(`Unknown effort "${options.effort}". Use one of: ${EFFORT_REQUESTED_VALUES.join(", ")}.`);
    }
    await startSession({
      effort: options.effort as EffortRequested,
      asJson,
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

const fix = program.command("fix").description("Remediation workflow");

fix
  .command("prompt <findingId>")
  .description("Print a remediation prompt for a coding agent")
  .action(async (findingId: string) => {
    const { sessionId } = globalOptions();
    const state = await currentSession(sessionId);
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

/* ---------- account, project, and platform ---------- */

program
  .command("link")
  .description("Install the agent skill and securely link this device to an account")
  .option("--url <url>", "app base URL")
  .option("--device-name <name>")
  .option("--no-open", "do not open a browser automatically")
  .option("--skip-skill-install", "link only, without installing the agent skill")
  .action(async (options: { url?: string; deviceName?: string; open?: boolean; skipSkillInstall?: boolean }) => {
    await linkCommand({
      ...(options.url ? { apiBaseUrl: options.url } : {}),
      ...(options.deviceName ? { deviceName: options.deviceName } : {}),
      ...(options.open === false ? { open: false } : {}),
      ...(options.skipSkillInstall ? { skipSkillInstall: true } : {})
    });
  });

program.command("login").description("Alias for link").action(async () => linkCommand());

program
  .command("install")
  .description("Install or update the portable agent skill for detected agents")
  .action(async () => installCommand());

program
  .command("status")
  .description("Show account, device, and quota state")
  .action(async () => statusCommand({ asJson: globalOptions().asJson }));

program.command("logout").description("Remove the local device credential").action(async () => logoutCommand());

program
  .command("config")
  .description("Local configuration")
  .argument("<subcommand>", "set-url")
  .argument("[value]")
  .action(async (subcommand: string, value?: string) => {
    if (subcommand !== "set-url" || !value) throw new Error('Usage: config set-url <url>');
    await setUrlCommand(value);
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
  .command("sync <localReportId>")
  .description("Sync an existing local report after rechecking login, device, and quota")
  .action(async (localReportId: string) => syncCommand(localReportId, { asJson: globalOptions().asJson }));

program
  .command("doctor")
  .description("Report what this machine and agent setup can assess")
  .action(async () => {
    await doctorCommand({ asJson: globalOptions().asJson });
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

program.parseAsync(process.argv).catch((error: unknown) => {
  fail(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
