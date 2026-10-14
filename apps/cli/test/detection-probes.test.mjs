/**
 * Environment detection must not have side effects it does not admit to.
 *
 * The defect these tests exist to keep fixed: detection ran `<agent> --version`
 * on every agent CLI it found, one of those CLIs bootstraps itself on first run,
 * and a single `myrqen status --agents` therefore wrote 247 files and 171 MB into
 * the home directory — while `myrqen link --dry-run` was printing "nothing was
 * written".
 *
 * So the fake agent CLI below does exactly what the real one did: it writes a
 * file the moment it starts. Every assertion here is about whether that file
 * appeared, because that file is the side effect, and no amount of careful
 * wording about intent is evidence that it did not happen.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import { existsSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

const ROOT = path.resolve(import.meta.dirname, "..", "..", "..");
const DIST = path.join(ROOT, "apps", "cli", "dist-tsc");
const CLI = path.join(ROOT, "apps", "cli", "dist", "myrqen.mjs");

const { whichExecutable } = await import(pathToFileURL(path.join(DIST, "integrations", "detect.js")).href);
const { createProbeLedger, probeRefusal, probeVersion, resolveProbeDecision, refusingLedger } = await import(
  pathToFileURL(path.join(DIST, "integrations", "probe.js")).href
);
const { ADAPTERS, detectAll } = await import(pathToFileURL(path.join(DIST, "integrations", "registry.js")).href);
const { codexAdapter } = await import(pathToFileURL(path.join(DIST, "integrations", "adapters", "misc.js")).href);
const { copilotAdapter } = await import(pathToFileURL(path.join(DIST, "integrations", "adapters", "copilot-gemini.js")).href);

const windows = process.platform === "win32";
/** Every case here builds a POSIX shell script, so Windows is out of scope for them. */
const posixOnly = windows ? test.skip : test;

/**
 * A machine of our own: a home directory, a repository, and a `PATH` containing
 * only what the test put there. Nothing reaches the real machine, and — because
 * `whichExecutable` reads the injected environment rather than `process.env` —
 * an agent installed on the developer's laptop cannot make a test pass.
 */
async function machine(overrides = {}) {
  const base = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-probe-"));
  const home = path.join(base, "home");
  const repoRoot = path.join(base, "repo");
  const bin = path.join(base, "bin");
  for (const directory of [home, repoRoot, bin]) await fs.mkdir(directory, { recursive: true });
  return {
    base,
    home,
    repoRoot,
    bin,
    marker: path.join(base, "bootstrapped"),
    context: {
      repoRoot,
      home,
      skillSource: "",
      platform: process.platform,
      env: { PATH: bin },
      probe: refusingLedger(),
      ...overrides
    }
  };
}

/**
 * An agent CLI that bootstraps on launch, the way GitHub Copilot's does.
 *
 * The marker is written before anything else, so it records the launch rather
 * than the successful completion of one. A CLI that is killed by the timeout has
 * still already done this much, which is precisely why a timeout is not a
 * substitute for not launching it.
 */
async function bootstrappingCli(fixture, name, { sleepSeconds = 0, prints = "1.2.3" } = {}) {
  const target = path.join(fixture.bin, name);
  const lines = ["#!/bin/sh", `printf 'bootstrapped by %s' "${name}" > "${fixture.marker}"`];
  if (sleepSeconds > 0) lines.push(`sleep ${sleepSeconds}`);
  lines.push(`echo "${name} version ${prints}"`);
  await fs.writeFile(target, `${lines.join("\n")}\n`, { mode: 0o755 });
  return target;
}

function allowingLedger() {
  return createProbeLedger({ allowed: true, reason: "this test asked for it" });
}

async function cleanup(...directories) {
  for (const directory of directories) await fs.rm(directory, { recursive: true, force: true });
}

/* ---------- the verdict costs nothing ---------- */

posixOnly("an agent is detected from PATH alone, and its own CLI is never launched", async () => {
  const fixture = await machine();
  try {
    await bootstrappingCli(fixture, "codex", { sleepSeconds: 30 });

    const started = Date.now();
    const detection = await codexAdapter.detect(fixture.context);
    const elapsed = Date.now() - started;

    assert.equal(detection.confidence, "confirmed", "the executable on PATH is proof on its own");
    assert.ok(
      detection.signals.some((signal) => signal.kind === "executable"),
      `expected an executable signal, got ${JSON.stringify(detection.signals)}`
    );
    assert.equal(detection.version, undefined, "no version, because nothing was asked");
    assert.equal(existsSync(fixture.marker), false, "the agent's CLI was never launched");
    assert.ok(elapsed < 2000, `detection took ${elapsed}ms; it should not wait on anything`);
  } finally {
    await cleanup(fixture.base);
  }
});

posixOnly("resolving PATH starts no process, and skips a directory wearing the same name", async () => {
  const fixture = await machine();
  try {
    // A directory called `codex` and a file called `aider` that nobody may run:
    // neither is an installed agent, and a `stat` is enough to know it.
    await fs.mkdir(path.join(fixture.bin, "codex"), { recursive: true });
    await fs.writeFile(path.join(fixture.bin, "aider"), "not executable\n", { mode: 0o644 });
    await bootstrappingCli(fixture, "opencode");

    assert.equal(await whichExecutable("codex", fixture.context), null, "a directory is not an executable");
    assert.equal(await whichExecutable("aider", fixture.context), null, "an unrunnable file is not an executable");
    assert.equal(await whichExecutable("opencode", fixture.context), path.join(fixture.bin, "opencode"));
    assert.equal(existsSync(fixture.marker), false, "resolving a name on PATH executes nothing");
  } finally {
    await cleanup(fixture.base);
  }
});

posixOnly("an empty PATH is silence, not an error", async () => {
  const fixture = await machine({ env: {} });
  try {
    assert.equal(await whichExecutable("codex", fixture.context), null);
    const detection = await codexAdapter.detect(fixture.context);
    assert.equal(detection.confidence, "absent");
  } finally {
    await cleanup(fixture.base);
  }
});

/* ---------- the version costs something, and is asked for on purpose ---------- */

posixOnly("a version is read only when the run permits it, and the launch is recorded", async () => {
  const fixture = await machine({ probe: allowingLedger() });
  try {
    await bootstrappingCli(fixture, "codex", { prints: "4.5.6" });

    const detection = await codexAdapter.detect(fixture.context);

    assert.equal(detection.confidence, "confirmed");
    assert.equal(detection.version, "4.5.6", "the version is read when it is allowed to be");
    assert.equal(existsSync(fixture.marker), true, "this fake really does write on launch");
    assert.deepEqual(
      fixture.context.probe.executed(),
      ["codex --version"],
      "the ledger names what was launched, so --dry-run can too"
    );
  } finally {
    await cleanup(fixture.base);
  }
});

posixOnly("a CLI that never answers is killed, the launch is still recorded, and nothing hangs", async () => {
  const fixture = await machine({ probe: allowingLedger() });
  try {
    await bootstrappingCli(fixture, "codex", { sleepSeconds: 60 });

    const started = Date.now();
    const detection = await codexAdapter.detect(fixture.context);
    const elapsed = Date.now() - started;

    assert.equal(detection.confidence, "confirmed", "the verdict never depended on the answer");
    assert.equal(detection.version, undefined, "an agent that cannot answer in time is unversioned");
    assert.ok(elapsed < 15000, `detection took ${elapsed}ms; the timeout is not being enforced`);
    assert.deepEqual(
      fixture.context.probe.executed(),
      ["codex --version"],
      "a probe that timed out still launched the program, and the ledger says so"
    );
  } finally {
    await cleanup(fixture.base);
  }
});

posixOnly("a version is never asked for before something that executed nothing confirms the agent", async () => {
  const fixture = await machine({ probe: allowingLedger() });
  try {
    const executable = await bootstrappingCli(fixture, "codex");
    const weak = [{ kind: "config_directory", detail: "~/.codex" }];

    const refusal = probeRefusal(fixture.context, { command: "codex", flag: "--version" }, weak);
    assert.match(refusal, /confirmed by a signal that executed nothing/);

    const version = await probeVersion(fixture.context, { command: "codex", flag: "--version" }, executable, weak);
    assert.equal(version, undefined);
    assert.equal(existsSync(fixture.marker), false, "a directory left behind does not license an execution");
    assert.deepEqual(fixture.context.probe.executed(), []);
  } finally {
    await cleanup(fixture.base);
  }
});

/* ---------- the per-adapter opt-out ---------- */

posixOnly("the GitHub Copilot CLI is never launched, whatever the run permits", async () => {
  const fixture = await machine({ probe: allowingLedger() });
  try {
    await bootstrappingCli(fixture, "copilot");

    const detection = await copilotAdapter.detect(fixture.context);

    assert.equal(detection.confidence, "confirmed", "the binary on PATH is the evidence");
    assert.equal(detection.version, undefined);
    assert.equal(existsSync(fixture.marker), false, "the CLI that caused all this is still not launched");
    assert.deepEqual(fixture.context.probe.executed(), []);

    const declared = copilotAdapter.probes.find((probe) => probe.command === "copilot");
    assert.ok(declared.never, "the adapter states the opt-out rather than relying on a call site");
    assert.equal(probeRefusal(fixture.context, declared, detection.signals), declared.never);
  } finally {
    await cleanup(fixture.base);
  }
});

posixOnly("no adapter executes a command it has not declared, and none executes an opted-out one", async () => {
  const declared = ADAPTERS.flatMap((adapter) => adapter.probes ?? []);
  const runnable = declared.filter((probe) => !probe.never);
  const fixture = await machine({ probe: allowingLedger() });
  try {
    // Every command any adapter might reach for, present and destructive. If a
    // call site ever executes something undeclared, the ledger will name it.
    for (const probe of declared) await bootstrappingCli(fixture, probe.command);
    for (const editor of ["code", "code-insiders", "cursor", "windsurf"]) await bootstrappingCli(fixture, editor);

    await detectAll(fixture.context);
    const executed = fixture.context.probe.executed();

    for (const line of executed) {
      const [command, flag] = line.split(" ");
      if (flag === "--list-extensions") {
        assert.ok(
          ["code", "code-insiders", "cursor", "windsurf"].includes(command),
          `${line} asked an editor Myrqen does not support`
        );
        continue;
      }
      assert.ok(
        runnable.some((probe) => `${probe.command} ${probe.flag}` === line),
        `${line} was executed but no adapter declares it`
      );
    }
    for (const probe of declared.filter((entry) => entry.never)) {
      assert.ok(
        !executed.some((line) => line.startsWith(`${probe.command} `)),
        `${probe.command} is opted out and must never be executed`
      );
    }
  } finally {
    await cleanup(fixture.base);
  }
});

posixOnly("a context that never asked about probing cannot execute anything", async () => {
  // The default an adapter fixture gets, and the default any future command gets
  // if it forgets to think about this.
  const fixture = await machine({ probe: undefined });
  try {
    await bootstrappingCli(fixture, "codex");
    const detection = await codexAdapter.detect(fixture.context);
    assert.equal(detection.confidence, "confirmed");
    assert.equal(existsSync(fixture.marker), false);
  } finally {
    await cleanup(fixture.base);
  }
});

/* ---------- the decision ---------- */

test("the probe decision follows the flag, then the environment, then the terminal", () => {
  const cases = [
    { input: { env: {}, stdoutIsTty: true, noProbe: true }, allowed: false, reason: /--no-probe/ },
    { input: { env: { MYRQEN_PROBE: "1" }, stdoutIsTty: true, noProbe: true }, allowed: false, reason: /--no-probe/ },
    { input: { env: { MYRQEN_NO_PROBE: "1" }, stdoutIsTty: true }, allowed: false, reason: /MYRQEN_NO_PROBE/ },
    { input: { env: { CI: "1" }, stdoutIsTty: true }, allowed: false, reason: /CI/ },
    { input: { env: {}, stdoutIsTty: false }, allowed: false, reason: /not a terminal/ },
    { input: { env: { MYRQEN_PROBE: "1", CI: "1" }, stdoutIsTty: false }, allowed: true, reason: /MYRQEN_PROBE/ },
    { input: { env: {}, stdoutIsTty: true }, allowed: true, reason: /terminal/ },
    // A variable set to nothing, or to a denial, is not a request.
    { input: { env: { MYRQEN_NO_PROBE: "" }, stdoutIsTty: true }, allowed: true, reason: /terminal/ },
    { input: { env: { CI: "false" }, stdoutIsTty: true }, allowed: true, reason: /terminal/ }
  ];

  for (const { input, allowed, reason } of cases) {
    const decision = resolveProbeDecision(input);
    assert.equal(decision.allowed, allowed, `${JSON.stringify(input)} -> ${JSON.stringify(decision)}`);
    assert.match(decision.reason, reason);
  }
});

/* ---------- what a dry run is allowed to claim ---------- */

const built = existsSync(CLI);
const endToEnd = built && !windows ? test : test.skip;

async function project() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-dryrun-repo-"));
  await fs.mkdir(path.join(root, ".git"), { recursive: true });
  await fs.writeFile(path.join(root, "package.json"), JSON.stringify({ name: "dry-run", version: "1.0.0" }, null, 2));
  return root;
}

/**
 * The CLI as a stranger runs it, with `PATH` replaced rather than extended so an
 * agent installed on the developer's laptop can never be launched by a test.
 */
function runCli(args, { cwd, home, bin, env = {} }) {
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      [CLI, ...args],
      {
        cwd,
        env: {
          HOME: home,
          USERPROFILE: home,
          PATH: bin,
          XDG_CONFIG_HOME: path.join(home, ".config"),
          MYRQEN_CONFIG_DIR: path.join(home, "cfg"),
          MYRQEN_NON_INTERACTIVE: "1",
          NO_COLOR: "1",
          MYRQEN_API_BASE_URL: "http://127.0.0.1:9",
          ...env
        },
        maxBuffer: 8 * 1024 * 1024
      },
      (error, stdout, stderr) => resolve({ code: error?.code ?? 0, stdout: String(stdout), stderr: String(stderr) })
    );
  });
}

/** Anything Myrqen would have written for the codex adapter at project scope. */
async function myrqenWroteAnything(repo, home) {
  for (const candidate of [
    path.join(repo, "AGENTS.md"),
    path.join(repo, ".agents"),
    path.join(repo, "CLAUDE.md"),
    path.join(home, ".agents")
  ]) {
    if (existsSync(candidate)) return candidate;
  }
  return null;
}

endToEnd("a dry run that executed nothing says so, and writes nothing", async () => {
  const fixture = await machine();
  const repo = await project();
  try {
    await bootstrappingCli(fixture, "codex");

    const dry = await runCli(["link", "--agent", "codex", "--scope", "project", "--dry-run"], {
      cwd: repo,
      home: fixture.home,
      bin: fixture.bin,
      env: { MYRQEN_NO_PROBE: "1" }
    });

    assert.equal(dry.code, 0, dry.stderr);
    assert.match(dry.stdout, /Dry run: nothing was written, and detecting your agents executed nothing\./);
    assert.equal(existsSync(fixture.marker), false, "--no-probe means the agent's CLI is not launched");
    assert.equal(await myrqenWroteAnything(repo, fixture.home), null, "a dry run writes nothing itself");
  } finally {
    await cleanup(fixture.base, repo);
  }
});

endToEnd("a dry run that launched an agent's CLI names it instead of implying nothing happened", async () => {
  const fixture = await machine();
  const repo = await project();
  try {
    await bootstrappingCli(fixture, "codex");

    const dry = await runCli(["link", "--agent", "codex", "--scope", "project", "--dry-run"], {
      cwd: repo,
      home: fixture.home,
      bin: fixture.bin,
      env: { MYRQEN_PROBE: "1" }
    });

    assert.equal(dry.code, 0, dry.stderr);
    assert.match(dry.stdout, /nothing was written by Myrqen/, "the promise is narrowed to the one Myrqen can keep");
    assert.match(dry.stdout, /codex --version/, "the line names what ran");
    assert.match(dry.stdout, /--no-probe/, "and says how to stop it");
    assert.doesNotMatch(
      dry.stdout,
      /Dry run: nothing was written\.$/m,
      "the old sentence claimed more than it could keep"
    );
    assert.equal(existsSync(fixture.marker), true, "the CLI really did run, which is why the line is needed");
    assert.equal(await myrqenWroteAnything(repo, fixture.home), null, "a dry run still writes nothing itself");
  } finally {
    await cleanup(fixture.base, repo);
  }
});

endToEnd("status and doctor detect without executing anything by default", async () => {
  const fixture = await machine();
  const repo = await project();
  try {
    await bootstrappingCli(fixture, "codex", { sleepSeconds: 30 });

    const started = Date.now();
    const status = await runCli(["status", "--agents", "--json"], {
      cwd: repo,
      home: fixture.home,
      bin: fixture.bin
    });
    const elapsed = Date.now() - started;

    assert.equal(status.code, 0, status.stderr);
    const payload = JSON.parse(status.stdout);
    assert.equal(payload.probe.allowed, false);
    assert.deepEqual(payload.probe.executed, []);
    assert.ok(
      payload.integrations.some((row) => row.id === "codex" && row.detected),
      `codex is still detected: ${status.stdout}`
    );
    assert.equal(existsSync(fixture.marker), false, "status --agents launched nothing");
    assert.ok(elapsed < 10000, `status took ${elapsed}ms`);

    const doctor = await runCli(["doctor", "--no-probe"], { cwd: repo, home: fixture.home, bin: fixture.bin });
    assert.match(doctor.stdout, /detection probes.*Executed nothing/s);
    assert.equal(existsSync(fixture.marker), false, "doctor launched nothing either");
  } finally {
    await cleanup(fixture.base, repo);
  }
});
