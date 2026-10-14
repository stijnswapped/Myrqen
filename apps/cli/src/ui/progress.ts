import type { ScanPhase, Severity } from "@myrqen/contracts";
import type { SessionState } from "../session/state.js";

/**
 * The live progress view.
 *
 * An assessment is eight declared phases, which is the right granularity for a
 * report and the wrong one for somebody watching a terminal. The view folds them
 * into the five stages the product describes everywhere else — Discover, Probe,
 * Settle, Fix, Retest — and shows the numbers that say whether the run is going
 * anywhere: findings by severity, how many were proved, how many unsafe actions
 * the policy refused.
 *
 * Two renderers, one model. A terminal gets a compact panel redrawn in place. A
 * pipe, a CI log, `NO_COLOR`, or `TERM=dumb` gets one plain line per change, so
 * an agent capturing stdout reads a log rather than cursor-control bytes. With
 * `--json` there is no progress output at all: stdout is one JSON document.
 *
 * No dependency: the panel is a handful of ANSI sequences, and a spinner library
 * would be the largest thing in a command that prints three lines.
 */

export type StageId = "discover" | "probe" | "settle" | "fix" | "retest";
export type StageState = "pending" | "running" | "complete";

export interface StageView {
  id: StageId;
  label: string;
  state: StageState;
  /** Wall-clock span of the stage, when it has started. */
  elapsedMs?: number;
}

export interface ProgressSnapshot {
  stages: StageView[];
  severity: Record<Severity, number>;
  /** Findings still standing: refuted ones are excluded. */
  findings: number;
  verified: number;
  refuted: number;
  refusedActions: number;
  fixed: number;
  scanState: string;
  /** A short free-text line under the panel, e.g. "running the static pass". */
  status?: string;
}

export const STAGE_PHASES: Readonly<Record<"discover" | "probe" | "settle", readonly ScanPhase[]>> = Object.freeze({
  discover: ["preflight", "scope", "discovery", "source_review"],
  probe: ["runtime_validation", "access_control"],
  settle: ["validation", "reporting"]
});

const LABELS: Record<StageId, string> = {
  discover: "Discover",
  probe: "Probe",
  settle: "Settle",
  fix: "Fix",
  retest: "Retest"
};

const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low", "info"];
const FINISHED_STATES = new Set(["complete", "cancelled", "failed", "policy_blocked"]);

function emptySeverity(): Record<Severity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

function span(starts: number[], ends: number[], running: boolean, now: number): number | undefined {
  if (starts.length === 0) return undefined;
  const from = Math.min(...starts);
  const to = running || ends.length === 0 ? now : Math.max(...ends);
  return Math.max(0, to - from);
}

function phaseStage(id: "discover" | "probe" | "settle", state: SessionState, now: number, settledSomething: boolean): StageView {
  const records = state.phases.filter((record) => STAGE_PHASES[id].includes(record.phase));
  const running = records.some((record) => record.state === "running");
  const finished = FINISHED_STATES.has(state.state);
  const starts = records.flatMap((record) => (record.startedAt ? [Date.parse(record.startedAt)] : []));
  const ends = records.flatMap((record) => (record.completedAt ? [Date.parse(record.completedAt)] : []));

  let stageState: StageState = "pending";
  if (running) stageState = "running";
  else if (records.length > 0) stageState = "complete";

  // Settling happens through `finding verify` and `finding refute` as much as
  // through a declared phase. A run that has settled candidates is settling,
  // whether or not the agent remembered to say so.
  if (id === "settle" && stageState === "pending" && settledSomething) stageState = finished ? "complete" : "running";
  if (id === "settle" && stageState === "complete" && !finished && !records.some((r) => r.phase === "reporting")) {
    stageState = records.length > 0 && records.every((r) => r.state === "complete") ? "complete" : "running";
  }

  const elapsedMs = span(starts, ends, stageState === "running", now);
  return { id, label: LABELS[id], state: stageState, ...(elapsedMs !== undefined ? { elapsedMs } : {}) };
}

function fixStages(state: SessionState, now: number): [StageView, StageView] {
  const history = state.findings.flatMap((finding) => finding.fixHistory ?? []);
  const fixEntries = history.filter((entry) => entry.action === "suggested" || entry.action === "applied");
  const retestEntries = history.filter((entry) => entry.action === "verified" || entry.action === "verification_failed");
  const inFlight = state.findings.some((finding) => finding.status === "fix_suggested" || finding.status === "fix_applied");

  const fixState: StageState = fixEntries.length === 0 ? "pending" : inFlight ? "running" : "complete";
  const fixTimes = fixEntries.map((entry) => Date.parse(entry.at));
  const retestTimes = retestEntries.map((entry) => Date.parse(entry.at));
  const fixElapsed = span(fixTimes, [...fixTimes, ...retestTimes], fixState === "running", now);

  const retestState: StageState = retestEntries.length === 0 ? "pending" : "complete";
  const retestElapsed = retestTimes.length > 0 ? Math.max(...retestTimes) - Math.min(...retestTimes) : undefined;

  return [
    { id: "fix", label: LABELS.fix, state: fixState, ...(fixElapsed !== undefined ? { elapsedMs: fixElapsed } : {}) },
    {
      id: "retest",
      label: LABELS.retest,
      state: retestState,
      ...(retestElapsed !== undefined ? { elapsedMs: retestElapsed } : {})
    }
  ];
}

/** The five-stage picture of a session at one instant. Pure: no I/O. */
export function snapshotFromSession(state: SessionState, now: Date = new Date(), status?: string): ProgressSnapshot {
  const at = now.getTime();
  const standing = state.findings.filter((finding) => finding.status !== "false_positive");
  const severity = emptySeverity();
  for (const finding of standing) severity[finding.severity] = (severity[finding.severity] ?? 0) + 1;

  const verified = standing.filter((finding) => finding.verification === "verified").length;
  const refuted = state.findings.length - standing.length;
  const [fix, retest] = fixStages(state, at);

  return {
    stages: [
      phaseStage("discover", state, at, false),
      phaseStage("probe", state, at, false),
      phaseStage("settle", state, at, verified + refuted > 0),
      fix,
      retest
    ],
    severity,
    findings: standing.length,
    verified,
    refuted,
    refusedActions: state.actionLog.filter((entry) => !entry.allowed).length,
    fixed: standing.filter((finding) => finding.status === "fixed_verified").length,
    scanState: state.state,
    ...(status ? { status } : {})
  };
}

/** A snapshot for the moment before a session exists: Discover is running. */
export function initialSnapshot(status?: string): ProgressSnapshot {
  return {
    stages: (Object.keys(LABELS) as StageId[]).map((id) => ({
      id,
      label: LABELS[id],
      state: id === "discover" ? "running" : "pending",
      ...(id === "discover" ? { elapsedMs: 0 } : {})
    })),
    severity: emptySeverity(),
    findings: 0,
    verified: 0,
    refuted: 0,
    refusedActions: 0,
    fixed: 0,
    scanState: "preflight",
    ...(status ? { status } : {})
  };
}

/* ------------------------------------------------------------------ modes */

export type ProgressMode = "live" | "plain" | "off";

export interface ModeInput {
  asJson?: boolean;
  isTTY?: boolean;
  env?: NodeJS.ProcessEnv;
}

/**
 * Which renderer this run gets. Live only in a real terminal that can draw it;
 * plain everywhere a human might still read the output; off for JSON.
 */
export function progressMode(input: ModeInput = {}): ProgressMode {
  if (input.asJson) return "off";
  const env = input.env ?? process.env;
  const isTTY = input.isTTY ?? Boolean(process.stdout.isTTY);
  if (!isTTY) return "plain";
  if (env.CI && env.CI !== "0" && env.CI !== "false") return "plain";
  if (env.NO_COLOR || env.MYRQEN_NO_COLOR === "1") return "plain";
  if (env.TERM === "dumb") return "plain";
  if (env.MYRQEN_NON_INTERACTIVE === "1") return "plain";
  return "live";
}

/* -------------------------------------------------------------- renderers */

export function formatDuration(ms: number | undefined): string {
  if (ms === undefined) return "";
  if (ms < 1000) return `${Math.round(ms)}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  const minutes = Math.floor(ms / 60_000);
  const seconds = Math.round((ms % 60_000) / 1000);
  return `${minutes}m${String(seconds).padStart(2, "0")}s`;
}

const SPINNER = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const ESC = "\u001b";

function paint(color: boolean, code: string, value: string): string {
  return color ? `${ESC}[${code}m${value}${ESC}[0m` : value;
}

/** One line: each of the five stages and how long it took. */
export function stageTimings(snapshot: ProgressSnapshot): string {
  return snapshot.stages
    .map((stage) => `${stage.label} ${stage.state === "pending" ? "-" : formatDuration(stage.elapsedMs) || "0ms"}`)
    .join(" · ");
}

export function severityLine(severity: Record<Severity, number>): string {
  return SEVERITIES.map((level) => `${level} ${severity[level] ?? 0}`).join(" · ");
}

const SHORT: Record<Severity, string> = { critical: "crit", high: "high", medium: "med", low: "low", info: "info" };

/** "crit 1 high 9 med 4 low 0": short enough for an 80-column panel. */
export function compactSeverity(severity: Record<Severity, number>): string {
  return SEVERITIES.filter((level) => level !== "info" || (severity.info ?? 0) > 0)
    .map((level) => `${SHORT[level]} ${severity[level] ?? 0}`)
    .join(" ");
}

/** The panel, as lines without trailing newlines. */
export function renderLive(snapshot: ProgressSnapshot, options: { frame?: number; color?: boolean } = {}): string[] {
  const color = options.color ?? true;
  const frame = options.frame ?? 0;
  const stages = snapshot.stages
    .map((stage) => {
      const mark =
        stage.state === "complete"
          ? paint(color, "38;5;114", "✓")
          : stage.state === "running"
            ? paint(color, "38;5;155", SPINNER[frame % SPINNER.length]!)
            : paint(color, "2", "·");
      const label = stage.state === "pending" ? paint(color, "2", stage.label) : stage.label;
      const time = stage.elapsedMs !== undefined && stage.state !== "pending" ? paint(color, "2", ` ${formatDuration(stage.elapsedMs)}`) : "";
      return `${mark} ${label}${time}`;
    })
    .join("   ");

  const counts = [
    `${snapshot.findings} finding${snapshot.findings === 1 ? "" : "s"}`,
    paint(color, "2", compactSeverity(snapshot.severity)),
    `${paint(color, "38;5;114", String(snapshot.verified))} verified`,
    `${snapshot.refusedActions} refused`,
    `${snapshot.fixed} fixed`
  ].join("  ");

  const lines = [stages, `  ${counts}`];
  if (snapshot.status) lines.push(`  ${paint(color, "2", snapshot.status)}`);
  return lines;
}

/** One line per thing that changed since `previous`. Stable and greppable. */
export function renderPlainChanges(previous: ProgressSnapshot | null, next: ProgressSnapshot): string[] {
  const lines: string[] = [];
  for (const stage of next.stages) {
    const before = previous?.stages.find((candidate) => candidate.id === stage.id);
    if (before?.state === stage.state) continue;
    if (!before && stage.state === "pending") continue;
    if (stage.state === "pending") continue;
    const time = stage.state === "complete" && stage.elapsedMs !== undefined ? ` ${formatDuration(stage.elapsedMs)}` : "";
    lines.push(`progress ${stage.id} ${stage.state}${time}`);
  }
  const countsChanged =
    !previous ||
    previous.findings !== next.findings ||
    previous.verified !== next.verified ||
    previous.refusedActions !== next.refusedActions ||
    previous.fixed !== next.fixed ||
    SEVERITIES.some((level) => previous.severity[level] !== next.severity[level]);
  if (countsChanged && (previous || next.findings > 0)) {
    lines.push(
      `progress findings ${next.findings} (${severityLine(next.severity)}) · verified ${next.verified} · refused ${next.refusedActions} · fixed ${next.fixed}`
    );
  }
  if (next.status && next.status !== previous?.status) lines.push(`progress ${next.status}`);
  return lines;
}

/* ------------------------------------------------------------------- view */

export interface ProgressStream {
  write(chunk: string): unknown;
  columns?: number;
}

/**
 * Draws snapshots. In live mode the panel is redrawn in place on a timer so the
 * spinner and the running stage's clock move between updates; `stop()` leaves
 * the last frame on screen and restores the cursor.
 */
export class ProgressView {
  private readonly mode: ProgressMode;
  private readonly stream: ProgressStream;
  private snapshot: ProgressSnapshot | null = null;
  private previous: ProgressSnapshot | null = null;
  private drawnLines = 0;
  private frame = 0;
  private timer: NodeJS.Timeout | null = null;
  private snapshotAt = Date.now();
  private readonly restore = (): void => this.showCursor();

  constructor(options: { mode: ProgressMode; stream?: ProgressStream }) {
    this.mode = options.mode;
    this.stream = options.stream ?? process.stdout;
  }

  get active(): boolean {
    return this.mode !== "off";
  }

  update(snapshot: ProgressSnapshot): void {
    if (this.mode === "off") return;
    this.snapshot = snapshot;
    this.snapshotAt = Date.now();
    if (this.mode === "plain") {
      for (const line of renderPlainChanges(this.previous, snapshot)) this.stream.write(`${line}\n`);
      this.previous = snapshot;
      return;
    }
    if (!this.timer) {
      this.stream.write(`${ESC}[?25l`);
      process.once("exit", this.restore);
      this.timer = setInterval(() => this.draw(true), 120);
      this.timer.unref?.();
    }
    this.draw(false);
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
      this.draw(false);
      this.showCursor();
      process.removeListener("exit", this.restore);
    }
  }

  /**
   * Stop and erase the panel. Used before a prompt, so a question is never
   * drawn into the middle of a panel that is still repainting.
   */
  clear(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
      process.removeListener("exit", this.restore);
    }
    if (this.mode === "live" && this.drawnLines > 0) {
      this.stream.write(`${ESC}[${this.drawnLines}A\r${ESC}[0J`);
      this.drawnLines = 0;
    }
    this.showCursor();
  }

  private showCursor(): void {
    if (this.mode === "live") this.stream.write(`${ESC}[?25h`);
  }

  private draw(tick: boolean): void {
    if (!this.snapshot) return;
    if (tick) this.frame += 1;
    // A running stage's clock keeps moving between updates.
    const since = Date.now() - this.snapshotAt;
    const shown: ProgressSnapshot = {
      ...this.snapshot,
      stages: this.snapshot.stages.map((stage) =>
        stage.state === "running" ? { ...stage, elapsedMs: (stage.elapsedMs ?? 0) + since } : stage
      )
    };
    // A pty with no size reports 0 columns: unknown, not tiny.
    const columns = this.stream.columns && this.stream.columns > 0 ? this.stream.columns : 100;
    const width = Math.max(40, columns);
    const lines = renderLive(shown, { frame: this.frame }).map((line) => truncate(line, width));
    const up = this.drawnLines > 0 ? `${ESC}[${this.drawnLines}A\r` : "";
    this.stream.write(`${up}${ESC}[0J${lines.join("\n")}\n`);
    this.drawnLines = lines.length;
  }
}

/** Truncate by visible width, leaving ANSI sequences intact. */
function truncate(line: string, width: number): string {
  let visible = 0;
  let out = "";
  for (let index = 0; index < line.length; index += 1) {
    if (line[index] === ESC) {
      const end = line.indexOf("m", index);
      if (end !== -1) {
        out += line.slice(index, end + 1);
        index = end;
        continue;
      }
    }
    if (visible >= width - 1) break;
    out += line[index];
    visible += 1;
  }
  return out;
}
