/**
 * The live progress view: five stages folded from eight phases, a compact panel
 * for a terminal, and plain lines for everything else — never cursor control in
 * a pipe, never anything at all next to --json.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { pathToFileURL } from "node:url";

const run = promisify(execFile);
const ROOT = path.resolve(import.meta.dirname, "..", "..", "..");
const progress = await import(pathToFileURL(path.join(ROOT, "apps", "cli", "dist-tsc", "ui", "progress.js")).href);

function session(overrides = {}) {
  return {
    state: "assessment",
    phases: [],
    findings: [],
    actionLog: [],
    ...overrides
  };
}

const T0 = Date.parse("2026-10-13T10:00:00.000Z");
const at = (ms) => new Date(T0 + ms).toISOString();

function finding(id, severity, extra = {}) {
  return { id, severity, verification: "needs_review", status: "open", ...extra };
}

test("phases fold into the five product stages with their own timings", () => {
  const state = session({
    phases: [
      { phase: "preflight", state: "complete", startedAt: at(0), completedAt: at(200) },
      { phase: "source_review", state: "complete", startedAt: at(200), completedAt: at(1700) },
      { phase: "runtime_validation", state: "running", startedAt: at(2000) }
    ]
  });
  const snapshot = progress.snapshotFromSession(state, new Date(T0 + 5000));
  const byId = Object.fromEntries(snapshot.stages.map((stage) => [stage.id, stage]));

  assert.deepEqual(
    snapshot.stages.map((stage) => stage.label),
    ["Discover", "Probe", "Settle", "Fix", "Retest"]
  );
  assert.equal(byId.discover.state, "complete");
  assert.equal(byId.discover.elapsedMs, 1700);
  assert.equal(byId.probe.state, "running");
  assert.equal(byId.probe.elapsedMs, 3000, "a running stage is timed up to now");
  assert.equal(byId.settle.state, "pending");
  assert.equal(byId.fix.state, "pending");
});

test("counts exclude refuted findings and count refused actions and fixes", () => {
  const state = session({
    findings: [
      finding("MYR-001", "high", { verification: "verified" }),
      finding("MYR-002", "high", { status: "false_positive" }),
      finding("MYR-003", "critical"),
      finding("MYR-004", "medium", {
        verification: "verified",
        status: "fixed_verified",
        fixHistory: [
          { at: at(100), action: "applied", verified: false },
          { at: at(900), action: "verified", verified: true }
        ]
      })
    ],
    actionLog: [
      { at: at(1), intent: "delete_all_orders", allowed: false },
      { at: at(2), intent: "read_order", allowed: true }
    ]
  });
  const snapshot = progress.snapshotFromSession(state, new Date(T0 + 1000));
  assert.equal(snapshot.findings, 3);
  assert.equal(snapshot.refuted, 1);
  assert.equal(snapshot.verified, 2);
  assert.equal(snapshot.refusedActions, 1);
  assert.equal(snapshot.fixed, 1);
  assert.deepEqual(snapshot.severity, { critical: 1, high: 1, medium: 1, low: 0, info: 0 });

  const byId = Object.fromEntries(snapshot.stages.map((stage) => [stage.id, stage]));
  assert.equal(byId.settle.state, "running", "verifying and refuting is settling, phase marked or not");
  assert.equal(byId.fix.state, "complete");
  assert.equal(byId.retest.state, "complete");
});

test("the renderer is chosen from the environment, and JSON always wins", () => {
  assert.equal(progress.progressMode({ asJson: true, isTTY: true, env: {} }), "off");
  assert.equal(progress.progressMode({ isTTY: true, env: {} }), "live");
  assert.equal(progress.progressMode({ isTTY: false, env: {} }), "plain");
  assert.equal(progress.progressMode({ isTTY: true, env: { CI: "true" } }), "plain");
  assert.equal(progress.progressMode({ isTTY: true, env: { NO_COLOR: "1" } }), "plain");
  assert.equal(progress.progressMode({ isTTY: true, env: { TERM: "dumb" } }), "plain");
  assert.equal(progress.progressMode({ isTTY: true, env: { CI: "false" } }), "live");
});

test("plain output is one greppable line per change and carries no escape codes", () => {
  const first = progress.initialSnapshot("mapping the project");
  const lines = [];
  const stream = { write: (chunk) => lines.push(chunk) };
  const view = new progress.ProgressView({ mode: "plain", stream });
  view.update(first);
  view.update(first);
  view.update({ ...first, findings: 2, severity: { ...first.severity, high: 2 } });
  view.stop();

  const text = lines.join("");
  assert.doesNotMatch(text, /\u001b/, "no ANSI in plain mode");
  assert.match(text, /^progress discover running$/m);
  assert.equal(text.match(/progress discover running/g).length, 1, "an unchanged snapshot prints nothing");
  assert.match(text, /^progress findings 2 \(critical 0 · high 2/m);
});

test("the live panel redraws in place and fits an 80-column terminal", () => {
  const writes = [];
  const stream = { write: (chunk) => writes.push(chunk), columns: 80 };
  const view = new progress.ProgressView({ mode: "live", stream });
  const snapshot = progress.initialSnapshot("running the static pass");
  view.update(snapshot);
  view.update({ ...snapshot, findings: 14 });
  view.stop();

  const all = writes.join("");
  assert.match(all, /\u001b\[\?25l/, "the cursor is hidden while drawing");
  assert.match(all, /\u001b\[\?25h/, "and restored afterwards");
  assert.match(all, /\u001b\[3A/, "the second frame moves up over the first");
  for (const line of progress.renderLive({ ...snapshot, findings: 14 }, { color: false })) {
    assert.ok(line.length <= 80, `"${line}" is ${line.length} columns`);
  }
});

test("stage timings read as one line", () => {
  const snapshot = progress.initialSnapshot();
  assert.equal(progress.stageTimings(snapshot), "Discover 0ms · Probe - · Settle - · Fix - · Retest -");
});

test("watch --once prints the current session's five stages without touching it", async () => {
  const CLI = path.join(ROOT, "apps", "cli", "dist", "myrqen.mjs");
  const env = { ...process.env, MYRQEN_TELEMETRY: "off", MYRQEN_ASSUME_NO_ISOLATION: "1", MYRQEN_AGENT_NAME: "test-harness" };
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-watch-"));
  try {
    await fs.writeFile(path.join(root, "package.json"), JSON.stringify({ name: "watched" }));
    await assert.rejects(run(process.execPath, [CLI, "watch", "--once"], { cwd: root, env }), /No session to watch/);
    await run(process.execPath, [CLI, "--json", "auto", "--sync", "no"], { cwd: root, env });
    const sessionDir = path.join(root, ".myrqen", "sessions");
    const [id] = await fs.readdir(sessionDir);
    const before = await fs.readFile(path.join(sessionDir, id, "session.json"), "utf8");

    const { stdout } = await run(process.execPath, [CLI, "--json", "watch"], { cwd: root, env });
    const snapshot = JSON.parse(stdout);
    assert.equal(snapshot.localReportId, id);
    assert.equal(snapshot.stages.find((stage) => stage.id === "discover").state, "complete");

    const { stdout: text } = await run(process.execPath, [CLI, "watch", "--once"], { cwd: root, env });
    assert.match(text, /Discover .*Probe .*Settle .*Fix .*Retest/);
    assert.doesNotMatch(text, /\u001b/);
    assert.equal(await fs.readFile(path.join(sessionDir, id, "session.json"), "utf8"), before, "watching is read-only");
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});
