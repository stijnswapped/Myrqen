import { execFile } from "node:child_process";
import type { AdapterContext, CommandProbe, DetectionSignal, ProbeDecision, ProbeLedger } from "./types.js";

/**
 * Executing somebody else's CLI, and admitting to it.
 *
 * This module exists because of a measured defect. Environment detection used to
 * run `<agent> --version` on every agent CLI it found, unconditionally. One of
 * those CLIs bootstraps itself on first run: a single `myrqen status --agents`
 * wrote 247 files and 171 MB into the home directory and took four seconds. The
 * timeout then killed the child before it answered, so the version was discarded
 * and the whole cost bought nothing. Meanwhile `myrqen link --dry-run` was
 * printing "nothing was written".
 *
 * The rules that follow from that, and that this file enforces:
 *
 *  - A version is a nicety printed next to a row. It is never evidence, and no
 *    confidence verdict may depend on it. `detect.ts` reaches its verdict from
 *    signals that execute nothing.
 *  - A third-party command runs only when this run's `ProbeDecision` allows it,
 *    only when the agent is already confirmed by a signal that executed nothing,
 *    and only when the adapter has declared that particular flag inert.
 *  - Every execution is written to a ledger before it starts, so `--dry-run` can
 *    name what ran instead of implying that nothing happened.
 */

/**
 * Long enough for a Node-based CLI to cold-start and answer.
 *
 * The old 1500 ms killed most of them mid-startup, which is the worst possible
 * trade: the child had already done whatever it does on launch, and Myrqen threw
 * the answer away. A probe that reliably times out is pure cost, so if we are
 * going to pay for the launch we wait long enough to learn something.
 */
const VERSION_TIMEOUT_MS = 3000;

/** Listing extensions is a bigger job than printing a version; editors are slower. */
const LISTING_TIMEOUT_MS = 4000;

/**
 * Run a command with a hard timeout and never throw.
 *
 * `execFile`'s own `timeout` sends SIGTERM and then waits for the child to agree
 * to die. A CLI that traps or ignores SIGTERM — several agent CLIs run their own
 * shutdown work — keeps `myrqen link` waiting for as long as it feels like
 * running. So the promise is settled on our own timer regardless of the child,
 * SIGKILL follows, and detection moves on. An agent that cannot answer in time is
 * reported as unversioned, never as a reason to hang.
 */
export async function execute(command: string, args: string[], timeoutMs: number): Promise<string | null> {
  return new Promise((resolve) => {
    let settled = false;
    let child: ReturnType<typeof execFile> | null = null;
    let timer: NodeJS.Timeout | null = null;

    const finish = (value: string | null): void => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolve(value);
    };

    timer = setTimeout(() => {
      try {
        child?.kill("SIGKILL");
      } catch {
        // The child may already be gone; the answer is the same either way.
      }
      finish(null);
    }, timeoutMs);
    timer.unref?.();

    try {
      child = execFile(
        command,
        args,
        { timeout: timeoutMs, killSignal: "SIGKILL", windowsHide: true, maxBuffer: 256 * 1024, encoding: "utf8" },
        (error, stdout) => finish(error ? null : String(stdout).trim() || null)
      );
      child.on("error", () => finish(null));
    } catch {
      finish(null);
    }
  });
}

/* ---------- the decision ---------- */

export interface ProbeDecisionInput {
  env: NodeJS.ProcessEnv;
  /** True when stdout is a terminal a person is watching. */
  stdoutIsTty: boolean;
  /** `--no-probe`, which beats everything else. */
  noProbe?: boolean;
}

function isTruthy(value: string | undefined): boolean {
  if (value === undefined) return false;
  const normalized = value.trim().toLowerCase();
  return normalized !== "" && normalized !== "0" && normalized !== "false" && normalized !== "no";
}

/**
 * May this run execute a third-party CLI at all?
 *
 * The default is off wherever nobody is watching. A version string is only worth
 * anything to a human reading a table, and an unattended run — a CI job, a shell
 * pipeline, a script parsing `--json` — gets exactly no value from it while
 * paying the full cost of whatever the agent's own CLI decides to do on launch.
 *
 * Both directions are overridable, because a default that cannot be argued with
 * becomes a thing people work around. `--no-probe` is the strongest statement
 * available and nothing outranks it; `MYRQEN_PROBE=1` is how an unattended run
 * says it wants the version column anyway and accepts what that costs.
 */
export function resolveProbeDecision(input: ProbeDecisionInput): ProbeDecision {
  if (input.noProbe === true) {
    return { allowed: false, reason: "--no-probe was passed" };
  }
  if (isTruthy(input.env.MYRQEN_NO_PROBE)) {
    return { allowed: false, reason: "MYRQEN_NO_PROBE is set" };
  }
  if (isTruthy(input.env.MYRQEN_PROBE)) {
    return { allowed: true, reason: "MYRQEN_PROBE is set" };
  }
  if (isTruthy(input.env.CI)) {
    return { allowed: false, reason: "CI is set" };
  }
  if (!input.stdoutIsTty) {
    return { allowed: false, reason: "stdout is not a terminal" };
  }
  return { allowed: true, reason: "an attended terminal, with neither --no-probe nor MYRQEN_NO_PROBE" };
}

/* ---------- the ledger ---------- */

/**
 * A ledger is mutable on purpose.
 *
 * Detection runs thirteen adapters concurrently and each one decides for itself
 * whether it has grounds to execute anything. Threading a return value back out
 * of every signal helper would change every signature in `detect.ts` for the
 * sake of a fact that only two lines of output ever read. One append-only record
 * on the context is the smaller, more honest shape: nothing outside this module
 * can rewrite what it holds, and `executed()` hands back a copy.
 */
export function createProbeLedger(decision: ProbeDecision): ProbeLedger {
  const lines: string[] = [];
  return {
    decision,
    record(commandLine: string): void {
      if (!lines.includes(commandLine)) lines.push(commandLine);
    },
    executed(): string[] {
      return [...lines];
    }
  };
}

/**
 * The ledger a command line builds for itself, from the real environment.
 *
 * `link`, `status`, and `doctor` each construct one and hand it to
 * `adapterContext`. Anything that does not — an adapter fixture in a test, a
 * future command that only reads files — gets `refusingLedger()` and therefore
 * executes nothing at all, which is the right default for code that never
 * thought about the question.
 */
export function detectionLedger(noProbe?: boolean): ProbeLedger {
  return createProbeLedger(
    resolveProbeDecision({
      env: process.env,
      stdoutIsTty: Boolean(process.stdout.isTTY),
      ...(noProbe === undefined ? {} : { noProbe })
    })
  );
}

/** A ledger that permits nothing. The default whenever nobody asked for probing. */
export function refusingLedger(): ProbeLedger {
  return createProbeLedger({ allowed: false, reason: "this command did not ask for version probing" });
}

/* ---------- running a probe ---------- */

/**
 * Do these signals confirm the agent without anything having been executed?
 *
 * An executable on `PATH` or an installed editor extension each prove the agent
 * is here, and `detect.ts` establishes both by reading the filesystem. This is
 * the precondition in rule form: a version is only ever an embellishment on a
 * verdict that already stands, so if the verdict does not stand yet, there is
 * nothing to embellish and no reason to launch anything.
 */
export function confirmedWithoutExecuting(signals: readonly DetectionSignal[]): boolean {
  return signals.some((signal) => signal.kind === "executable" || signal.kind === "extension");
}

/** Why a probe did not run, or null when it may. Exported so `doctor` and tests can ask. */
export function probeRefusal(
  context: AdapterContext,
  probe: CommandProbe,
  signals: readonly DetectionSignal[]
): string | null {
  if (probe.never) return probe.never;
  const decision = context.probe?.decision;
  if (!decision) return "this command did not ask for version probing";
  if (!decision.allowed) return decision.reason;
  if (!confirmedWithoutExecuting(signals)) {
    return `${probe.command} is not confirmed by a signal that executed nothing`;
  }
  return null;
}

/**
 * Execute one declared, inert command — or decline, and say nothing.
 *
 * The order of the checks matters. `probe.never` comes first because an adapter
 * saying "do not execute this one" is a statement about the program itself, not
 * about this run, and no flag or terminal should be able to talk it round.
 */
async function runProbe(
  context: AdapterContext,
  probe: CommandProbe,
  executablePath: string,
  signals: readonly DetectionSignal[],
  timeoutMs: number
): Promise<string | null> {
  if (probeRefusal(context, probe, signals) !== null) return null;
  // Recorded before the spawn, not after. Whatever the child does to the home
  // directory it does on launch, so an execution that times out still happened
  // and `--dry-run` still has to name it.
  context.probe?.record(`${probe.command} ${probe.flag}`);
  return execute(executablePath, [probe.flag], timeoutMs);
}

/**
 * A version string, trimmed to one short line.
 *
 * Whatever a third-party binary prints ends up in Myrqen's own table. A version
 * string carrying escape sequences could repaint or erase the rows around it, so
 * only printable characters survive the trip.
 */
export function parseVersion(output: string | null): string | undefined {
  if (!output) return undefined;
  const lines = output.split(/\r?\n/);
  const line = lines.find((candidate) => /\d+\.\d+/.test(candidate)) ?? lines[0];
  if (!line) return undefined;
  const match = /\d+\.\d+(\.\d+)?([-+][0-9A-Za-z.\-]+)?/.exec(line);
  return (
    (match?.[0] ?? line)
      .replace(/[\u0000-\u001f\u007f-\u009f]/g, "")
      .slice(0, 40)
      .trim() || undefined
  );
}

/**
 * The version next to an agent's row, when it is free to have and safe to ask
 * for. `undefined` in every other case, and never an error: a missing version
 * changes nothing about what Myrqen will do.
 */
export async function probeVersion(
  context: AdapterContext,
  probe: CommandProbe,
  executablePath: string,
  signals: readonly DetectionSignal[]
): Promise<string | undefined> {
  return parseVersion(await runProbe(context, probe, executablePath, signals, VERSION_TIMEOUT_MS));
}

/**
 * The lines an editor's CLI prints for `--list-extensions`.
 *
 * Only reached when the extensions directory did not answer the question, and
 * only when this run permits execution — see `editorExtension` in `detect.ts`
 * for why that order is the right way round.
 */
export async function probeListing(
  context: AdapterContext,
  probe: CommandProbe,
  executablePath: string,
  signals: readonly DetectionSignal[]
): Promise<string | null> {
  return runProbe(context, probe, executablePath, signals, LISTING_TIMEOUT_MS);
}
