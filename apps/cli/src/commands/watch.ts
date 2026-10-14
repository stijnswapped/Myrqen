import { BRAND } from "@myrqen/brand";
import { findRepoRoot } from "../discovery/project.js";
import { loadSession } from "../session/state.js";
import { blank, json, write } from "../ui/output.js";
import {
  ProgressView,
  progressMode,
  renderLive,
  snapshotFromSession,
  stageTimings,
  type ProgressSnapshot
} from "../ui/progress.js";

const POLL_MS = 500;
const FINISHED = new Set(["complete", "cancelled", "failed", "policy_blocked"]);

/**
 * `watch`: follow the current session from another terminal.
 *
 * The agent drives a scan through many short CLI calls, each of which exits.
 * Nothing in that loop owns the screen, so the live view is its own command: it
 * reads the session file the agent's calls write, redraws when it changes, and
 * stops when the session finishes. It is read-only and never touches the session.
 */
export async function watchCommand(options: { asJson?: boolean; once?: boolean; sessionId?: string; intervalMs?: number }): Promise<void> {
  const repoRoot = await findRepoRoot(process.cwd());
  const first = await loadSession(repoRoot, options.sessionId);
  if (!first) {
    throw new Error(`No session to watch here. Start one with "${BRAND.cliName} auto" (or ask your agent to).`);
  }

  if (options.once || options.asJson) {
    const snapshot = snapshotFromSession(first);
    if (options.asJson) json({ localReportId: first.localReportId, ...snapshot });
    else for (const line of renderLive(snapshot, { color: false })) write(line);
    return;
  }

  const mode = progressMode();
  const view = new ProgressView({ mode });
  const id = first.localReportId;
  let last: ProgressSnapshot = snapshotFromSession(first);
  view.update({ ...last, status: `watching ${id} · Ctrl+C to stop` });

  let stopped = false;
  const stop = (): void => {
    stopped = true;
  };
  process.once("SIGINT", stop);

  try {
    while (!stopped) {
      await new Promise((resolve) => setTimeout(resolve, options.intervalMs ?? POLL_MS));
      // A poll can land mid-write and read half a file; the next poll reads it whole.
      const state = await loadSession(repoRoot, id).catch(() => null);
      if (!state) continue;
      last = snapshotFromSession(state);
      if (FINISHED.has(state.state)) {
        view.update({ ...last, status: `session ${state.state}` });
        break;
      }
      view.update({ ...last, status: `watching ${id} · Ctrl+C to stop` });
    }
  } finally {
    process.removeListener("SIGINT", stop);
    view.stop();
  }

  if (FINISHED.has(last.scanState)) {
    blank();
    write(stageTimings(last));
    write(`Open the report with "${BRAND.cliName} report".`);
  }
}
