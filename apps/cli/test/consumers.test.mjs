/**
 * Public-consumer simulation.
 *
 * These tests run the built CLI as a stranger would: as a child process, in a
 * throwaway project, against a throwaway home directory, with no workspace
 * resolution and no account. Every assertion is about what a user would see —
 * files on disk and text on stdout — rather than about an internal function,
 * because the failures worth catching here are the ones where the code is right
 * and the packaging, the paths, or the prompts are wrong.
 *
 * `HOME` is redirected per test so detection sees a machine we constructed. On
 * POSIX `os.homedir()` honours it; the Windows-shaped case sets `USERPROFILE`
 * too and asserts only on behaviour that is platform-independent.
 *
 * `PATH` is replaced, not extended, for the same reason: it points at a `bin`
 * directory inside that throwaway home, so an agent installed on the machine
 * running the tests can neither make a case pass nor change what it links. A
 * case that needs an installed agent puts one there with `installAgent`.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, readFile, writeFile, rm, stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import os from "node:os";
import path from "node:path";

const CLI = path.resolve(import.meta.dirname, "..", "dist", "myrqen.mjs");

const built = existsSync(CLI);
const describeIfBuilt = built ? test : test.skip;

async function scratch(prefix) {
  return mkdtemp(path.join(os.tmpdir(), `myrqen-${prefix}-`));
}

/** A project directory with a git marker, so repo-root discovery stops there. */
async function project(name) {
  const root = await scratch(name);
  await mkdir(path.join(root, ".git"), { recursive: true });
  await writeFile(path.join(root, "package.json"), JSON.stringify({ name, version: "1.0.0" }, null, 2));
  return root;
}

/** Where `installAgent` puts executables, and the only directory on `PATH`. */
function binDirectory(home) {
  return path.join(home, ".local", "bin");
}

/**
 * An agent CLI on `PATH`: the evidence detection grades as "confirmed".
 *
 * Detection only asks whether the file exists and is runnable; it executes
 * nothing, and with `CI` set the version probe is refused too. The body exits
 * cleanly anyway, so a regression that did launch it would not hang the run.
 * Windows decides runnability by `PATHEXT`, so the fixture there is a `.cmd`.
 */
async function installAgent(home, name) {
  const bin = binDirectory(home);
  await mkdir(bin, { recursive: true });
  if (process.platform === "win32") {
    await writeFile(path.join(bin, `${name}.cmd`), "@exit /b 0\r\n");
  } else {
    await writeFile(path.join(bin, name), "#!/bin/sh\nexit 0\n", { mode: 0o755 });
  }
}

/** The parent's environment minus every spelling of `PATH`; Windows keeps it as `Path`. */
function environmentWithoutPath() {
  return Object.fromEntries(Object.entries(process.env).filter(([key]) => key.toUpperCase() !== "PATH"));
}

function run(args, { cwd, home, env = {} } = {}) {
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      [CLI, ...args],
      {
        cwd,
        env: {
          ...environmentWithoutPath(),
          PATH: binDirectory(home),
          HOME: home,
          USERPROFILE: home,
          XDG_CONFIG_HOME: path.join(home, ".config"),
          MYRQEN_CONFIG_DIR: path.join(home, ".myrqen-config"),
          MYRQEN_NON_INTERACTIVE: "1",
          NO_COLOR: "1",
          CI: "1",
          ...env
        },
        maxBuffer: 8 * 1024 * 1024
      },
      (error, stdout, stderr) =>
        resolve({ code: error?.code ?? 0, stdout: String(stdout), stderr: String(stderr) })
    );
  });
}

async function cleanup(...directories) {
  // Retries, because Windows refuses to remove a directory while any process
  // still has it open, and the CLI that just exited is not always the last one.
  for (const directory of directories) {
    await rm(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
  }
}

/* ---------- Consumer A: Claude Code and Cursor on the machine ---------- */

describeIfBuilt("consumer A: two detected agents, link, idempotence, unlink", async () => {
  const home = await scratch("home-a");
  const repo = await project("consumer-a");
  try {
    // A machine that has both tools: their documented configuration directories
    // and their CLIs on PATH. The directories alone grade "probable", and
    // `--all` deliberately links only what is "confirmed", so without the
    // executables this case passed only on a laptop that had the real agents.
    await mkdir(path.join(home, ".claude"), { recursive: true });
    await mkdir(path.join(home, ".claude", "skills"), { recursive: true });
    await mkdir(path.join(home, ".cursor"), { recursive: true });
    await installAgent(home, "claude");
    await installAgent(home, "cursor");

    const dry = await run(["link", "--all", "--scope", "project", "--dry-run"], { cwd: repo, home });
    assert.equal(dry.code, 0, dry.stderr);
    assert.match(dry.stdout, /Detected coding agents/);

    const before = await run(["status", "--agents", "--json"], { cwd: repo, home });
    const beforeState = JSON.parse(before.stdout);
    assert.ok(
      beforeState.integrations.every((row) => row.linked === false),
      "nothing is linked before the first run"
    );

    const first = await run(["link", "--all", "--scope", "project", "--yes"], { cwd: repo, home });
    assert.equal(first.code, 0, first.stderr);

    const after = await run(["status", "--agents", "--json"], { cwd: repo, home });
    const afterState = JSON.parse(after.stdout);
    const linked = afterState.integrations.filter((row) => row.linked);
    for (const id of ["claude-code", "cursor"]) {
      assert.ok(
        linked.some((row) => row.id === id),
        `${id} is confirmed by its CLI on PATH, so --all links it; got ${after.stdout}`
      );
    }
    assert.ok(
      linked.every((row) => row.status === "healthy"),
      `every linked integration reports healthy: ${JSON.stringify(linked)}`
    );

    // Idempotence: a second identical run must change nothing.
    const second = await run(["link", "--all", "--scope", "project", "--yes"], { cwd: repo, home });
    assert.equal(second.code, 0, second.stderr);
    assert.match(second.stdout, /already up to date|already current|up to date/i);

    const removed = await run(["unlink", "--all", "--yes"], { cwd: repo, home });
    assert.equal(removed.code, 0, removed.stderr);

    const final = await run(["status", "--agents", "--json"], { cwd: repo, home });
    assert.ok(
      JSON.parse(final.stdout).integrations.every((row) => row.linked === false),
      "unlink removed every integration"
    );
  } finally {
    await cleanup(home, repo);
  }
});

/* ---------- Consumer D: a project that already has instruction files ---------- */

const USER_AGENTS_MD = `# Engineering conventions

We use pnpm. Never commit to main directly.

## Testing
Every pull request needs a regression test.
`;

const USER_CLAUDE_MD = `# Project notes for Claude

The API lives in apps/api. Prefer small commits.
`;

const USER_COPILOT_MD = `Use TypeScript strict mode in this repository.
`;

describeIfBuilt("consumer D: existing instructions are preserved byte for byte", async () => {
  const home = await scratch("home-d");
  const repo = await project("consumer-d");
  try {
    await mkdir(path.join(home, ".claude"), { recursive: true });
    await mkdir(path.join(repo, ".github"), { recursive: true });
    await writeFile(path.join(repo, "AGENTS.md"), USER_AGENTS_MD);
    await writeFile(path.join(repo, "CLAUDE.md"), USER_CLAUDE_MD);
    await writeFile(path.join(repo, ".github", "copilot-instructions.md"), USER_COPILOT_MD);

    const linked = await run(["link", "--all", "--scope", "project", "--yes"], { cwd: repo, home });
    assert.equal(linked.code, 0, linked.stderr);

    for (const [relative, original] of [
      ["AGENTS.md", USER_AGENTS_MD],
      ["CLAUDE.md", USER_CLAUDE_MD],
      [path.join(".github", "copilot-instructions.md"), USER_COPILOT_MD]
    ]) {
      const contents = await readFile(path.join(repo, relative), "utf8");
      for (const line of original.split("\n").filter((value) => value.trim().length > 0)) {
        assert.ok(contents.includes(line), `${relative} still contains: ${line}`);
      }
    }

    // And unlinking must give the files back exactly as the user wrote them.
    const removed = await run(["unlink", "--all", "--yes"], { cwd: repo, home });
    assert.equal(removed.code, 0, removed.stderr);

    for (const [relative, original] of [
      ["AGENTS.md", USER_AGENTS_MD],
      ["CLAUDE.md", USER_CLAUDE_MD],
      [path.join(".github", "copilot-instructions.md"), USER_COPILOT_MD]
    ]) {
      const full = path.join(repo, relative);
      if (!existsSync(full)) continue;
      const contents = await readFile(full, "utf8");
      assert.ok(!/myrqen:start/.test(contents), `${relative} has no Myrqen region left`);
      for (const line of original.split("\n").filter((value) => value.trim().length > 0)) {
        assert.ok(contents.includes(line), `${relative} kept: ${line}`);
      }
    }
  } finally {
    await cleanup(home, repo);
  }
});

/* ---------- Consumer C: nothing installed ---------- */

describeIfBuilt("consumer C: a machine with no coding agent still gets a usable answer", async () => {
  const home = await scratch("home-c");
  const repo = await project("consumer-c");
  try {
    const result = await run(["link", "--dry-run"], { cwd: repo, home });
    assert.equal(result.code, 0, result.stderr);
    assert.match(result.stdout, /No coding agent was detected|Not detected/);
    // It must not have written anything on a dry run, and it must not have
    // errored simply because the machine is bare.
    assert.doesNotMatch(result.stdout, /Error/i);

    // An explicit choice still works with nothing detected: AGENTS.md is a
    // convention, not an installed program.
    const explicit = await run(["link", "--agent", "agents-md", "--scope", "project", "--yes"], {
      cwd: repo,
      home
    });
    assert.equal(explicit.code, 0, explicit.stderr);
    const agentsMd = path.join(repo, "AGENTS.md");
    assert.ok(existsSync(agentsMd), "AGENTS.md was created when asked for explicitly");
    assert.match(await readFile(agentsMd, "utf8"), /myrqen:start/);
  } finally {
    await cleanup(home, repo);
  }
});

/* ---------- Consumer B: Windows-shaped paths and CRLF ---------- */

describeIfBuilt("consumer B: a CRLF instruction file keeps its line endings", async () => {
  const home = await scratch("home-b");
  const repo = await project("consumer-b");
  try {
    await writeFile(path.join(repo, "AGENTS.md"), USER_AGENTS_MD.replace(/\n/g, "\r\n"));

    const linked = await run(["link", "--agent", "agents-md", "--scope", "project", "--yes"], {
      cwd: repo,
      home
    });
    assert.equal(linked.code, 0, linked.stderr);

    const contents = await readFile(path.join(repo, "AGENTS.md"), "utf8");
    assert.ok(contents.includes("\r\n"), "CRLF line endings survived the merge");
    assert.ok(!/[^\r]\n/.test(contents), "no LF-only line was introduced");
  } finally {
    await cleanup(home, repo);
  }
});

/* ---------- Consumer E: a stale integration is upgraded, not duplicated ---------- */

describeIfBuilt("consumer E: a stale managed region is rewritten once", async () => {
  const home = await scratch("home-e");
  const repo = await project("consumer-e");
  try {
    await writeFile(
      path.join(repo, "AGENTS.md"),
      `${USER_AGENTS_MD}\n<!-- myrqen:start v1 -->\nold payload from an earlier release\n<!-- myrqen:end -->\n`
    );

    const linked = await run(["link", "--agent", "agents-md", "--scope", "project", "--yes"], {
      cwd: repo,
      home
    });
    assert.equal(linked.code, 0, linked.stderr);

    const contents = await readFile(path.join(repo, "AGENTS.md"), "utf8");
    const regions = contents.match(/myrqen:start/g) ?? [];
    assert.equal(regions.length, 1, "exactly one managed region after an upgrade");
    assert.ok(!contents.includes("old payload from an earlier release"), "the stale payload is gone");
    assert.ok(contents.includes("We use pnpm."), "the user's own text is untouched");
  } finally {
    await cleanup(home, repo);
  }
});

/* ---------- Non-TTY and machine-readable behaviour ---------- */

describeIfBuilt("non-interactive link with no flags changes nothing and says how to choose", async () => {
  const home = await scratch("home-n");
  const repo = await project("consumer-n");
  try {
    const result = await run(["link"], { cwd: repo, home });
    assert.equal(result.code, 0, result.stderr);
    assert.ok(!existsSync(path.join(repo, "AGENTS.md")), "nothing was written without a choice");
  } finally {
    await cleanup(home, repo);
  }
});

describeIfBuilt("--json emits valid JSON on stdout and no decoration", async () => {
  const home = await scratch("home-j");
  const repo = await project("consumer-j");
  try {
    const result = await run(["--json", "status", "--agents"], { cwd: repo, home });
    assert.equal(result.code, 0, result.stderr);
    const parsed = JSON.parse(result.stdout);
    assert.ok(Array.isArray(parsed.integrations), "status --json returns an integrations array");
    assert.doesNotMatch(result.stdout, /\[/, "no ANSI escapes in JSON output");
  } finally {
    await cleanup(home, repo);
  }
});

describeIfBuilt("doctor runs on a bare machine and reports rather than throwing", async () => {
  const home = await scratch("home-doc");
  const repo = await project("consumer-doc");
  try {
    const result = await run(["doctor", "--json"], { cwd: repo, home, env: { MYRQEN_API_BASE_URL: "http://127.0.0.1:1" } });
    assert.equal(result.code, 0, result.stderr);
    const parsed = JSON.parse(result.stdout);
    assert.ok(Array.isArray(parsed.checks) && parsed.checks.length > 0, "doctor produced checks");
    assert.ok(
      parsed.checks.some((check) => check.name === "agents"),
      "doctor reports on agent integrations"
    );
  } finally {
    await cleanup(home, repo);
  }
});

describeIfBuilt("unlink on a project with nothing installed is not an error", async () => {
  const home = await scratch("home-u");
  const repo = await project("consumer-u");
  try {
    const result = await run(["unlink", "--all", "--yes"], { cwd: repo, home });
    assert.equal(result.code, 0, result.stderr);
    assert.match(result.stdout, /No .* integration was found/i);
  } finally {
    await cleanup(home, repo);
  }
});

describeIfBuilt("the packaged skill bundle ships beside the binary", async () => {
  const info = await stat(path.resolve(import.meta.dirname, "..", "skill", "SKILL.md"));
  assert.ok(info.isFile(), "skill/SKILL.md is present next to dist/");
});
