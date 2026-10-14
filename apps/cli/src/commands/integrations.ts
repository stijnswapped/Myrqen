import path from "node:path";
import { BRAND, CLI_VERSION } from "@myrqen/brand";
import { findRepoRoot } from "../discovery/project.js";
import { adapterContext } from "../integrations/context.js";
import { detectionLedger } from "../integrations/probe.js";
import { adapterById, adapterIds, detectAll, recommendedSelection, type DetectedAdapter } from "../integrations/registry.js";
import { applyPlan, type AppliedPlan } from "../integrations/apply.js";
import { planIsNoop, planSummaryLine, renderApplied, renderPlans } from "../integrations/plan.js";
import { displayPath, isWritable, pathExists, readsBackUnchanged } from "../integrations/managed.js";
import type { AdapterContext, DetectionConfidence, InstallPlan, Scope, ValidationResult } from "../integrations/types.js";
import { blank, bullet, capabilityNote, fail, field, heading, json, style, write } from "../ui/output.js";
import { confirm, isInteractive } from "../ui/prompt.js";
import { multiSelectHelp, selectMany, selectOne } from "../ui/select.js";

/**
 * The setup experience.
 *
 * The shape of this command is the product's first impression, and the thing it
 * has to earn is permission to write files in someone's project and home
 * directory. So the order is fixed: say where we are, say what we found, let the
 * user choose, show exactly what will change, ask, then do it and say what
 * happened. Nothing is written before the plan has been printed.
 */

const CONFIDENCE_LABEL: Record<DetectionConfidence, string> = {
  confirmed: "Confirmed",
  probable: "Probable",
  project_only: "Project configuration found",
  absent: "Not detected"
};

export interface LinkIntegrationOptions {
  /** Explicit adapter ids from `--agent`. */
  agents?: string[];
  /** `--all`: every detected agent, no prompt. */
  all?: boolean;
  scope?: Scope | "both";
  dryRun?: boolean;
  yes?: boolean;
  asJson?: boolean;
  /** Print every file in the plan rather than collapsing a bundle to its directory. */
  verbose?: boolean;
  /**
   * `--no-probe`: reach the detection verdict without executing anything.
   *
   * Costs the version column and nothing else. Already the default outside an
   * attended terminal; the flag is for the case where the terminal is attended
   * and the user would still rather Myrqen kept its hands to itself.
   */
  noProbe?: boolean;
}

function detectionLine(entry: DetectedAdapter): string {
  const marker = entry.detection.detected ? style.brand("●") : style.dim("○");
  const label = entry.adapter.displayName.padEnd(18);
  const state = CONFIDENCE_LABEL[entry.detection.confidence];
  const linked = entry.linkedScopes.length > 0 ? style.dim(`  linked (${entry.linkedScopes.join(", ")})`) : "";
  const version = entry.detection.version ? style.dim(`  ${entry.detection.version}`) : "";
  return `  ${marker} ${label} ${state}${version}${linked}`;
}

function environmentBlock(context: AdapterContext): void {
  write(style.bold("Project"));
  write(`  ${displayPath(context.repoRoot, context.repoRoot, context.home) === "" ? context.repoRoot : abbreviateHome(context.repoRoot, context.home)}`);
  blank();
  write(style.bold("Environment"));
  write(`  ${platformName(context.platform)}`);
  write(`  Node ${process.versions.node}`);
  write(`  ${BRAND.displayName} ${CLI_VERSION}`);
  blank();
}

function abbreviateHome(target: string, home: string): string {
  const relative = path.relative(home, target);
  return relative && !relative.startsWith("..") && !path.isAbsolute(relative)
    ? `~/${relative.split(path.sep).join("/")}`
    : target;
}

function platformName(platform: NodeJS.Platform): string {
  if (platform === "darwin") return "macOS";
  if (platform === "win32") return "Windows";
  if (platform === "linux") return process.env.WSL_DISTRO_NAME ? `Linux (WSL: ${process.env.WSL_DISTRO_NAME})` : "Linux";
  return platform;
}

/**
 * Which agents to install for.
 *
 * Explicit flags win and never prompt, because a script that passes `--agent`
 * must behave the same on every machine. Otherwise the recommended set — the
 * agents Myrqen is sure about — is offered pre-ticked, and the user can change
 * it. In a non-interactive shell with no flags, nothing is selected and the
 * command says how to choose, rather than picking on the user's behalf.
 */
async function chooseAgents(
  detected: DetectedAdapter[],
  options: LinkIntegrationOptions
): Promise<DetectedAdapter[] | null> {
  if (options.agents && options.agents.length > 0) {
    const chosen: DetectedAdapter[] = [];
    for (const id of options.agents) {
      const entry = detected.find((candidate) => candidate.adapter.id === id);
      if (!entry) {
        throw new Error(
          `Unknown agent "${id}". Supported agents: ${adapterIds().join(", ")}.`
        );
      }
      chosen.push(entry);
    }
    return chosen;
  }

  const installable = detected.filter((entry) => entry.scopes.length > 0);
  const recommended = recommendedSelection(detected);

  // `--all` means every agent Myrqen is SURE about. Including `probable` and
  // `project_only` wrote files for agents that were not on the machine, which
  // is the exact behaviour the confidence ladder exists to prevent. A user who
  // wants a merely-probable agent can still name it with `--agent`.
  if (options.all) return installable.filter((entry) => entry.detection.confidence === "confirmed");

  if (!isInteractive()) {
    // Nothing is chosen for the user in a shell that cannot answer. Returning
    // the recommended set here built a plan, printed it, had `confirm()` decline
    // it, and reported "Nothing was changed." — which reads as a bug rather than
    // as the instruction it was meant to be.
    return [];
  }

  const mode = await selectOne(`Where should ${BRAND.displayName} be linked?`, [
    {
      value: "recommended",
      label: "Recommended — all detected agents",
      hint: recommended.length > 0 ? recommended.map((entry) => entry.adapter.displayName).join(", ") : "nothing detected"
    },
    { value: "select", label: "Select agents" },
    { value: "agents-md", label: "Shared AGENTS.md only", hint: "one file, read by several agents" },
    { value: "none", label: "Nothing for now" }
  ]);

  if (mode === null || mode === "none") return null;
  if (mode === "recommended") return recommended;
  if (mode === "agents-md") return detected.filter((entry) => entry.adapter.id === "agents-md");

  const picked = await selectMany(
    `Select agents  ${style.dim(multiSelectHelp())}`,
    installable.map((entry) => ({
      value: entry.adapter.id,
      label: entry.adapter.displayName,
      hint: `${CONFIDENCE_LABEL[entry.detection.confidence]}${entry.linkedScopes.length > 0 ? " · already linked" : ""}`,
      selected: recommended.some((candidate) => candidate.adapter.id === entry.adapter.id)
    }))
  );
  if (picked === null) return null;
  return installable.filter((entry) => picked.includes(entry.adapter.id));
}

async function chooseScopes(
  selection: DetectedAdapter[],
  options: LinkIntegrationOptions
): Promise<Map<string, Scope[]>> {
  const chosen = new Map<string, Scope[]>();

  const requested: Scope[] | null =
    options.scope === "both" ? ["project", "global"] : options.scope ? [options.scope] : null;

  if (requested) {
    for (const entry of selection) {
      chosen.set(entry.adapter.id, requested.filter((scope) => entry.scopes.includes(scope)));
    }
    return chosen;
  }

  // Project is the default everywhere. It is the scope a user can review in a
  // diff, commit for their team, and delete by deleting a directory — and it is
  // the one that cannot surprise them in an unrelated repository next week.
  const supportsGlobal = selection.some((entry) => entry.scopes.includes("global"));
  let answer: string | null = "project";
  if (supportsGlobal && isInteractive() && !options.yes) {
    answer = await selectOne("Scope", [
      { value: "project", label: "This project", hint: "version-controllable, and only affects this repository" },
      { value: "global", label: "Global where supported", hint: "applies to every project you open" },
      { value: "both", label: "Both" }
    ]);
  }
  if (answer === null) answer = "project";

  for (const entry of selection) {
    const wanted: Scope[] =
      answer === "both" ? ["project", "global"] : answer === "global" ? ["global"] : ["project"];
    let usable = wanted.filter((scope) => entry.scopes.includes(scope));
    // An agent that only supports the other scope still deserves an install
    // rather than a silent skip, but the user is told which scope it used.
    if (usable.length === 0 && entry.scopes.length > 0) usable = [entry.scopes[0]!];
    chosen.set(entry.adapter.id, usable);
  }
  return chosen;
}

export async function linkIntegrations(options: LinkIntegrationOptions = {}): Promise<AppliedPlan[]> {
  const repoRoot = await findRepoRoot(process.cwd());
  const context = await adapterContext(repoRoot, { probe: detectionLedger(options.noProbe) });
  const detected = await detectAll(context);

  if (options.asJson) {
    // Machine consumers get the whole picture in one document: what is
    // installed, what would change, and nothing decorative.
    //
    // Selection comes from flags only. Reaching an interactive picker here
    // paints cursor escapes onto the stream the caller is parsing and then waits
    // for a keypress that is never coming, which is the worst of both outcomes.
    if (!options.agents?.length && !options.all) {
      json({
        project: repoRoot,
        probe: serializeProbe(context),
        agents: detected.map(serializeDetection),
        plans: [],
        applied: [],
        error: {
          code: "NO_SELECTION",
          message: `With --json, name the agents explicitly: --agent <id> (repeatable) or --all.`
        }
      });
      process.exitCode = 2;
      return [];
    }
    // Writing needs an explicit yes even here. "Nothing is written before the
    // plan has been accepted" is the product's contract, and a machine caller
    // accepts by passing --yes rather than by being a machine.
    if (!options.dryRun && !options.yes) {
      const plans = await buildPlans(context, (await chooseAgents(detected, options)) ?? [], await chooseScopes((await chooseAgents(detected, options)) ?? [], options));
      json({
        project: repoRoot,
        probe: serializeProbe(context),
        agents: detected.map(serializeDetection),
        plans: plans.map(serializePlan),
        applied: [],
        error: {
          code: "CONFIRMATION_REQUIRED",
          message: "Add --yes to apply this plan, or --dry-run to ask for it explicitly."
        }
      });
      process.exitCode = 2;
      return [];
    }
    const selection = (await chooseAgents(detected, options)) ?? [];
    const scopes = await chooseScopes(selection, options);
    const plans = await buildPlans(context, selection, scopes);
    if (options.dryRun) {
      json({
        project: repoRoot,
        probe: serializeProbe(context),
        agents: detected.map(serializeDetection),
        plans: plans.map(serializePlan)
      });
      return [];
    }
    const applied: AppliedPlan[] = [];
    for (const plan of plans) applied.push(await applyPlan(plan));
    json({
      project: repoRoot,
      probe: serializeProbe(context),
      agents: detected.map(serializeDetection),
      applied: applied.map(serializeApplied)
    });
    if (applied.some((result) => !result.ok)) process.exitCode = 1;
    return applied;
  }

  heading("link");
  blank();
  environmentBlock(context);

  write(style.bold("Detected coding agents"));
  for (const entry of detected) write(detectionLine(entry));
  blank();

  const undetected = detected.filter((entry) => !entry.detection.detected);
  if (undetected.length === detected.length) {
    capabilityNote(
      `No coding agent was detected on this machine. The universal "${BRAND.cliName} auto" command works from any agent with shell access, and a shared AGENTS.md is readable by several of them.`
    );
    blank();
  }

  const selection = await chooseAgents(detected, options);
  if (selection === null) {
    write("Nothing was changed.");
    return [];
  }
  if (selection.length === 0) {
    write("No agent was selected, so nothing was changed.");
    if (!isInteractive()) {
      const detectedNames = detected.filter((entry) => entry.detection.detected).map((entry) => entry.adapter.id);
      capabilityNote(
        `This shell cannot prompt, so nothing is chosen for you. Name what you want: "${BRAND.cliName} link --agent <id> --yes"${
          detectedNames.length > 0 ? ` — detected here: ${detectedNames.join(", ")}` : ""
        }, or "${BRAND.cliName} link --all --yes" for every detected agent.`
      );
    }
    return [];
  }

  const scopes = await chooseScopes(selection, options);
  const plans = await buildPlans(context, selection, scopes);

  if (plans.length === 0) {
    // No plan at all is not the same as nothing to do. It means every agent
    // asked for supports neither the scope requested nor any other, and saying
    // "already up to date" would report a refusal as a success.
    const requested = options.scope ? `at ${options.scope} scope` : "";
    fail(
      `None of the agents you named can be installed ${requested}. ${selection
        .map((entry) => `${entry.adapter.displayName} supports ${entry.scopes.join(" and ") || "no scope on this platform"}`)
        .join("; ")}.`
    );
    process.exitCode = 2;
    return [];
  }

  blank();
  write(style.bold(`Ready to link ${BRAND.displayName}`));
  blank();
  renderPlans(plans, { verbose: options.verbose === true });

  if (plans.every(planIsNoop)) {
    write(`Everything is already up to date. Run "${BRAND.cliName} status" to see it.`);
    return [];
  }

  write(planSummaryLine(plans));
  blank();

  if (options.dryRun) {
    write(style.dim(dryRunSummary(context)));
    return [];
  }

  const proceed = options.yes || (await confirm("Continue?", { defaultYes: true }));
  if (!proceed) {
    write("Nothing was changed.");
    return [];
  }

  blank();
  const applied: AppliedPlan[] = [];
  for (const plan of plans) applied.push(await applyPlan(plan));
  renderApplied(applied);
  // A script that calls this must be able to tell that it failed.
  if (applied.some((result) => !result.ok)) process.exitCode = 1;
  blank();
  write(style.bold("Next"));
  bullet(`Run "${BRAND.cliName} status" to confirm what is installed.`);
  bullet(`Run "${BRAND.cliName} auto" in a project you own to start an assessment.`);
  return applied;
}

/**
 * Build every plan, and let one adapter's failure cost only its own row.
 *
 * Planning reads files, and reading files fails: a permission, a directory where
 * a file was expected, a config too malformed to parse. An exception escaping
 * here aborted the whole command and installed nothing — including for the
 * agents whose plans were already correct — and showed the user a raw stack.
 */
async function buildPlans(
  context: AdapterContext,
  selection: DetectedAdapter[],
  scopes: Map<string, Scope[]>
): Promise<InstallPlan[]> {
  const plans: InstallPlan[] = [];
  for (const entry of selection) {
    for (const scope of scopes.get(entry.adapter.id) ?? []) {
      try {
        plans.push(await entry.adapter.createInstallPlan(context, scope));
      } catch (error) {
        plans.push({
          adapterId: entry.adapter.id,
          displayName: entry.adapter.displayName,
          scope,
          writes: [
            {
              path: "",
              displayPath: `${entry.adapter.displayName} (${scope})`,
              action: "blocked",
              preservesExistingContent: false,
              reason: `its configuration could not be read: ${
                error instanceof Error ? error.message : "unknown error"
              }`
            }
          ],
          notes: [
            `Every other agent in this run is unaffected. Run "${BRAND.cliName} doctor" for what to check.`
          ]
        });
      }
    }
  }
  return Promise.all(plans.map(guardWrites));
}

/**
 * Turn a write that cannot succeed into a `blocked` row, before the user agrees
 * to anything.
 *
 * Two conditions, both of which used to surface as a raw error at apply time —
 * after the plan had been shown and accepted, with a message naming a temporary
 * file that no longer existed.
 *
 * A read-only target is the more interesting of the two, because the write would
 * otherwise *succeed*: a temp file plus a rename needs write permission on the
 * directory, not on the file, so `chmod 444 CLAUDE.md` was silently defeated.
 * Somebody who marks a file read-only has said something, and the answer is to
 * report it, not to route around it.
 */
async function guardWrites(plan: InstallPlan): Promise<InstallPlan> {
  const writes = await Promise.all(
    plan.writes.map(async (write_) => {
      if (write_.action === "unchanged" || write_.action === "blocked" || !write_.path) return write_;

      if (!(await isWritable(write_.path))) {
        return {
          ...write_,
          action: "blocked" as const,
          reason: (await pathExists(write_.path))
            ? "the file is read-only; change its permissions or remove it and run this again"
            : "its directory is not writable"
        };
      }
      if (!(await readsBackUnchanged(write_.path))) {
        return {
          ...write_,
          action: "blocked" as const,
          reason:
            "the file is not valid UTF-8, and rewriting it would replace the bytes that are not — edit it by hand, or convert it first"
        };
      }
      return write_;
    })
  );
  return { ...plan, writes };
}

/**
 * What a dry run may honestly claim.
 *
 * The old line was "Dry run: nothing was written." — true about Myrqen, and
 * read by everybody as "nothing happened". It was printed on runs where
 * detection had just launched an agent's own CLI, which on at least one agent
 * unpacks itself into the home directory. The promise Myrqen can actually keep
 * is narrower than the one that sentence made, so the sentence says the narrower
 * thing and then names what ran.
 *
 * `executed()` is the record of launches, not of successes: a probe that timed
 * out still started the program, and the program had already done whatever it
 * does on launch.
 */
function dryRunSummary(context: AdapterContext): string {
  const executed = context.probe?.executed() ?? [];
  if (executed.length === 0) {
    return "Dry run: nothing was written, and detecting your agents executed nothing.";
  }
  return `Dry run: nothing was written by ${BRAND.displayName} — but detecting your agents ran ${listOf(
    executed
  )}, and what those programs do on their own is theirs to decide. Pass --no-probe to skip them.`;
}

/** "a", "a and b", "a, b and c" — so a list reads as part of the sentence. */
function listOf(items: readonly string[]): string {
  if (items.length <= 1) return items[0] ?? "";
  return `${items.slice(0, -1).join(", ")} and ${items[items.length - 1]}`;
}

/* ---------- status ---------- */

export async function integrationStatus(
  options: { asJson?: boolean; collect?: boolean; noProbe?: boolean } = {}
): Promise<Record<string, unknown> | void> {
  const repoRoot = await findRepoRoot(process.cwd());
  const context = await adapterContext(repoRoot, { probe: detectionLedger(options.noProbe) });
  const detected = await detectAll(context);

  const rows: Array<{
    id: string;
    name: string;
    detected: boolean;
    confidence: DetectionConfidence;
    linked: boolean;
    scope: string;
    target: string;
    status: string;
    detail?: string;
    remedy?: string;
  }> = [];

  for (const entry of detected) {
    const installed = await entry.adapter.installed(context).catch(() => []);
    if (installed.length === 0) {
      rows.push({
        id: entry.adapter.id,
        name: entry.adapter.displayName,
        detected: entry.detection.detected,
        confidence: entry.detection.confidence,
        linked: false,
        scope: "—",
        target: "—",
        status: entry.detection.detected ? "not linked" : "not detected"
      });
      continue;
    }
    for (const integration of installed) {
      const validation = await entry.adapter
        .validate(context, integration)
        .catch((): ValidationResult => ({ health: "conflicted", detail: "This integration file could not be read or parsed." }));
      rows.push({
        id: entry.adapter.id,
        name: entry.adapter.displayName,
        detected: entry.detection.detected,
        confidence: entry.detection.confidence,
        linked: true,
        scope: integration.scope,
        target: integration.displayPath,
        status: validation.health,
        detail: validation.detail,
        // A row that is not healthy always gets an instruction. An adapter that
        // reports a problem without a remedy still leaves the user holding a
        // word — "missing" — and no idea what to type; re-running link is the
        // right answer for every state this command can report.
        ...(validation.health === "healthy"
          ? {}
          : { remedy: validation.remedy ?? `Run "${BRAND.cliName} link --agent ${entry.adapter.id}" to repair it.` })
      });
    }
  }

  const executed = context.probe?.executed() ?? [];
  const payload = {
    cliVersion: CLI_VERSION,
    project: repoRoot,
    integrations: rows,
    // Machine consumers get the same admission the terminal gets. A caller
    // diffing their home directory after a `status --json` deserves to know
    // which programs this command started.
    probe: {
      allowed: context.probe?.decision.allowed ?? false,
      reason: context.probe?.decision.reason ?? "no probe policy was supplied",
      executed
    }
  };
  if (options.collect) return payload;
  if (options.asJson) {
    json(payload);
    return;
  }

  write(`${BRAND.displayName} ${CLI_VERSION}`);
  blank();
  const widthName = Math.max(...rows.map((row) => row.name.length), 6);
  write(
    style.dim(
      `${"Agent".padEnd(widthName)}  ${"Detected".padEnd(9)}${"Linked".padEnd(8)}${"Scope".padEnd(9)}${"Status".padEnd(18)}Target`
    )
  );
  for (const row of rows) {
    const status =
      row.status === "healthy"
        ? style.ok("healthy")
        : row.status === "stale"
          ? style.warn("update available")
          : row.status === "conflicted"
            ? style.bad("conflicted")
            : style.dim(row.status);
    write(
      `${row.name.padEnd(widthName)}  ${(row.detected ? "yes" : "no").padEnd(9)}${(row.linked ? "yes" : "no").padEnd(8)}${row.scope.padEnd(9)}${status.padEnd(18)}${style.dim(row.target)}`
    );
  }
  if (executed.length > 0) {
    blank();
    write(style.dim(`Detection ran ${listOf(executed)} to read a version. Pass --no-probe to skip that.`));
  }
  const remedies = rows.filter((row) => row.remedy);
  if (remedies.length > 0) {
    blank();
    write(style.bold("What to do"));
    for (const row of remedies) {
      bullet(`${row.name} (${row.scope}): ${row.detail ? `${row.detail} ` : ""}${row.remedy}`);
    }
  }
}

/* ---------- unlink ---------- */

export interface UnlinkOptions {
  agents?: string[];
  all?: boolean;
  /**
   * Limit the removal to one scope.
   *
   * Without it, `unlink --agent claude-code` removes that agent's integration
   * everywhere it is installed, including the global one — which is right when a
   * user is removing Myrqen, and a nasty surprise when they meant "take it out
   * of this repository". The plan says so before it happens, but `--yes` skips
   * the plan, so the flag is what makes the narrow intent expressible.
   */
  scope?: Scope;
  yes?: boolean;
  dryRun?: boolean;
  asJson?: boolean;
}

export async function unlinkIntegrations(options: UnlinkOptions = {}): Promise<void> {
  const repoRoot = await findRepoRoot(process.cwd());
  const context = await adapterContext(repoRoot);

  const present: Array<{ id: string; name: string; scope: Scope; target: string }> = [];
  for (const id of adapterIds()) {
    const adapter = adapterById(id)!;
    for (const integration of await adapter.installed(context).catch(() => [])) {
      present.push({ id, name: adapter.displayName, scope: integration.scope, target: integration.displayPath });
    }
  }

  if (present.length === 0) {
    if (options.asJson) json({ removed: [] });
    else write(`No ${BRAND.displayName} integration was found in this project or for this user.`);
    return;
  }

  let chosen = options.scope ? present.filter((entry) => entry.scope === options.scope) : present;
  if (options.agents && options.agents.length > 0) {
    chosen = chosen.filter((entry) => options.agents!.includes(entry.id));
  } else if (!options.all) {
    if (!isInteractive()) {
      throw new Error(
        `Choose what to remove with "${BRAND.cliName} unlink --agent <id>" or remove everything with "${BRAND.cliName} unlink --all".`
      );
    }
    const picked = await selectMany(
      `Remove which integrations?  ${style.dim(multiSelectHelp())}`,
      chosen.map((entry) => ({
        value: `${entry.id}:${entry.scope}`,
        label: `${entry.name} (${entry.scope})`,
        hint: entry.target,
        selected: true
      }))
    );
    if (picked === null) {
      write("Nothing was changed.");
      return;
    }
    chosen = chosen.filter((entry) => picked.includes(`${entry.id}:${entry.scope}`));
  }

  if (chosen.length === 0) {
    write("Nothing was selected, so nothing was changed.");
    return;
  }

  const plans: InstallPlan[] = [];
  for (const entry of chosen) {
    plans.push(await adapterById(entry.id)!.createUninstallPlan(context, entry.scope));
  }

  if (!options.asJson) {
    heading("unlink");
    blank();
    renderPlans(plans);
    if (chosen.some((entry) => entry.scope === "global")) {
      capabilityNote(
        `One or more of these is a global integration, which affects every project on this machine. Pass "--scope project" to remove only this repository's.`
      );
    }
    capabilityNote(
      `Only content ${BRAND.displayName} wrote is removed. Instructions you added yourself stay exactly as they are.`
    );
    blank();
  }

  if (options.dryRun) {
    if (options.asJson) json({ plans: plans.map(serializePlan) });
    else write(style.dim("Dry run: nothing was removed."));
    return;
  }

  if (!options.yes && !options.asJson && !(await confirm("Remove these?", { defaultYes: true }))) {
    write("Nothing was changed.");
    return;
  }

  const applied: AppliedPlan[] = [];
  for (const plan of plans) applied.push(await applyPlan(plan));
  if (options.asJson) json({ applied: applied.map(serializeApplied) });
  else renderApplied(applied);
}

/* ---------- serialization for --json ---------- */

/**
 * The probe policy and its consequences, for a caller that cannot read the
 * terminal line. Same facts, same words.
 */
function serializeProbe(context: AdapterContext) {
  return {
    allowed: context.probe?.decision.allowed ?? false,
    reason: context.probe?.decision.reason ?? "no probe policy was supplied",
    executed: context.probe?.executed() ?? []
  };
}

function serializeDetection(entry: DetectedAdapter) {
  return {
    agent: entry.adapter.id,
    displayName: entry.adapter.displayName,
    detected: entry.detection.detected,
    confidence: entry.detection.confidence,
    signals: entry.detection.signals.map((signal) => signal.kind),
    ...(entry.detection.version ? { version: entry.detection.version } : {}),
    scopes: entry.scopes,
    linkedScopes: entry.linkedScopes
  };
}

function serializePlan(plan: InstallPlan) {
  return {
    agent: plan.adapterId,
    scope: plan.scope,
    writes: plan.writes.map((write_) => ({
      path: write_.displayPath,
      action: write_.action,
      preservesExistingContent: write_.preservesExistingContent,
      ...(write_.reason ? { reason: write_.reason } : {})
    })),
    notes: plan.notes
  };
}

function serializeApplied(applied: AppliedPlan) {
  return {
    agent: applied.plan.adapterId,
    scope: applied.plan.scope,
    ok: applied.ok,
    writes: applied.writes.map((entry) => ({
      path: entry.write.displayPath,
      outcome: entry.outcome,
      ...(entry.error ? { error: entry.error } : {})
    }))
  };
}

/** Used by `doctor` so its integration checks and `status` cannot disagree. */
export async function integrationHealth(context: AdapterContext) {
  const results: Array<{ name: string; health: string; detail: string; remedy?: string }> = [];
  for (const id of adapterIds()) {
    const adapter = adapterById(id)!;
    for (const integration of await adapter.installed(context).catch(() => [])) {
      const validation = await adapter
        .validate(context, integration)
        .catch((): ValidationResult => ({ health: "conflicted", detail: "This integration file could not be read or parsed." }));
      results.push({
        name: `${adapter.displayName} (${integration.scope})`,
        health: validation.health,
        detail: validation.detail,
        ...(validation.remedy ? { remedy: validation.remedy } : {})
      });
    }
  }
  return results;
}

void field;
