/**
 * Windows and WSL, without a Windows machine.
 *
 * `AdapterContext` carries `platform`, `home`, and `env` precisely so the path
 * handling can be driven from a fixture, and this file is the reason that
 * indirection exists: every adapter is planned twice, once against a
 * Windows-shaped context (`win32`, `C:\Users\dev`) and once against a
 * WSL-shaped one (`linux`, `/home/dev`, `WSL_DISTRO_NAME` set), and the paths
 * they name are checked before anything of the sort reaches a user.
 *
 * What these assertions really cover, stated plainly so nobody reads more into
 * a green run than is there:
 *
 *  - The WSL half is exact. WSL is Linux with POSIX paths, so `node:path` on the
 *    machine running these tests behaves as it does inside a distribution, and
 *    every assertion below is the real thing.
 *  - The Windows half checks *derivation*, not `node:path`'s Windows semantics.
 *    The adapters call `path.join`, which resolves to `path.posix` on a POSIX
 *    host, so what is proven here is that every path an adapter names is built
 *    from the injected home, the repository root, or an environment override —
 *    never from `os.homedir()`, a hard-coded `/Users/...`, or a separator the
 *    adapter typed itself. That is the class of bug this suite can catch off
 *    Windows, and it is the class that has actually shipped in tools like this.
 *    Whether `path.win32.join` then assembles those parts correctly is Node's
 *    responsibility, and only a Windows host can demonstrate it.
 *  - The CRLF cases are exact on any host: line-ending handling is ordinary
 *    string work in `managed.ts`, and the platform flag only decides which
 *    branches an adapter takes on the way there.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

const ROOT = path.resolve(import.meta.dirname, "..", "..", "..");
const DIST = path.join(ROOT, "apps", "cli", "dist-tsc");
const SKILL_SOURCE = path.join(ROOT, "packages", "skill", "myrqen");

const { ADAPTERS, adapterById } = await import(pathToFileURL(path.join(DIST, "integrations", "registry.js")).href);
const { displayPath } = await import(pathToFileURL(path.join(DIST, "integrations", "managed.js")).href);
const { applyPlan } = await import(pathToFileURL(path.join(DIST, "integrations", "apply.js")).href);

/**
 * A Windows machine, described rather than borrowed.
 *
 * Built with `path.win32` so the fixture is shaped the way Windows shapes it —
 * a drive letter and backslashes — whatever host reads this file.
 */
const WINDOWS_HOME = path.win32.join("C:\\", "Users", "dev");
const WINDOWS_REPO = path.win32.join(WINDOWS_HOME, "source", "checkout");

/** WSL: a Linux home inside the distribution, never the Windows one under /mnt. */
const WSL_HOME = "/home/dev";
const WSL_REPO = "/home/dev/source/checkout";

/**
 * The WSL half is exact only where `node:path` is POSIX, as the header says. On a
 * Windows host it is `path.win32`, which turns `/home/dev` into `\home\dev` and
 * resolves it onto the current drive, so these cases would be measuring the host
 * rather than the adapters. The Windows half runs for real there instead.
 */
const WSL_NEEDS_POSIX_HOST =
  path.sep === "/" ? false : "WSL paths are POSIX paths, and on a Windows host node:path is path.win32";

function windowsContext(env = {}) {
  return { repoRoot: WINDOWS_REPO, home: WINDOWS_HOME, skillSource: SKILL_SOURCE, platform: "win32", env };
}

function wslContext(env = {}) {
  return {
    repoRoot: WSL_REPO,
    home: WSL_HOME,
    skillSource: SKILL_SOURCE,
    platform: "linux",
    env: { WSL_DISTRO_NAME: "Ubuntu", ...env }
  };
}

/**
 * Every write every adapter would make, install and uninstall alike.
 *
 * Uninstall plans are included because they name paths too, and a plan that
 * looks in the wrong place quietly reports "nothing to remove" instead of
 * failing — the worst possible answer for an uninstall.
 */
async function plannedWrites(context) {
  const rows = [];
  for (const adapter of ADAPTERS) {
    for (const scope of adapter.supportedScopes(context)) {
      for (const [kind, build] of [
        ["install", adapter.createInstallPlan],
        ["uninstall", adapter.createUninstallPlan]
      ]) {
        const plan = await build.call(adapter, context, scope);
        for (const write of plan.writes) rows.push({ adapter: adapter.id, scope, kind, write });
      }
    }
  }
  return rows;
}

/** Is `target` the root itself or something under it, under either separator? */
function under(target, root) {
  return target === root || target.startsWith(`${root}/`) || target.startsWith(`${root}\\`);
}

function describe(row) {
  return `${row.adapter} ${row.scope} ${row.kind}: ${row.write.path}`;
}

/* ---------- where the paths land ---------- */

test("every path a Windows plan names is under the injected home or the repository", async () => {
  const rows = await plannedWrites(windowsContext());
  assert.ok(rows.length > 20, "the sweep actually planned something for every adapter");

  for (const row of rows) {
    assert.ok(
      under(row.write.path, WINDOWS_HOME) || under(row.write.path, WINDOWS_REPO),
      `${describe(row)} escaped both roots`
    );
    // The strongest single signal that an adapter read the context instead of
    // the machine: this process's real home may never appear in a plan built
    // for somebody else's.
    assert.ok(!row.write.path.includes(os.homedir()), `${describe(row)} leaked the running machine's home`);
  }
});

test("no adapter emits a POSIX-only absolute path on win32", async () => {
  for (const row of await plannedWrites(windowsContext())) {
    assert.ok(!row.write.path.startsWith("/"), `${describe(row)} is rooted at a POSIX /`);
    assert.match(row.write.path, /^[A-Za-z]:/, `${describe(row)} is not on a drive`);
  }
});

test("no adapter mixes separators into the part of a path it builds itself", async () => {
  // Only the tail is examined, and deliberately. The fixture's roots carry
  // whatever separators the fixture chose — backslashes for the Windows one —
  // while the segments after the root are the adapter's own work, joined by
  // whichever `node:path` the host provides. So the check is: the adapter added
  // nothing but the host's separator. On Windows that reads as "no forward
  // slashes"; here it reads as "no backslashes"; either way a separator an
  // adapter typed into a string literal fails it.
  const foreign = path.sep === "\\" ? "/" : "\\";

  for (const context of [windowsContext(), wslContext()]) {
    for (const row of await plannedWrites(context)) {
      const root = under(row.write.path, context.repoRoot) ? context.repoRoot : context.home;
      const tail = row.write.path.slice(root.length);
      assert.ok(!tail.includes(foreign), `${describe(row)} joined its own segments with ${foreign}`);
    }
  }
});

test("every path a WSL plan names stays inside the distribution", { skip: WSL_NEEDS_POSIX_HOST }, async () => {
  const rows = await plannedWrites(wslContext());
  for (const row of rows) {
    assert.ok(
      under(row.write.path, WSL_HOME) || under(row.write.path, WSL_REPO),
      `${describe(row)} escaped both roots`
    );
    // A Windows-aware integration that "helpfully" wrote to the host's
    // C: drive would put the file where the Linux agent never looks, and
    // where a Windows agent would read it with the wrong project attached.
    assert.ok(!row.write.path.startsWith("/mnt/"), `${describe(row)} reached out to the Windows host filesystem`);
    assert.ok(!/^[A-Za-z]:/.test(row.write.path), `${describe(row)} named a drive letter inside WSL`);
  }
});

/* ---------- environment overrides ---------- */

test("CODEX_HOME and CLAUDE_CONFIG_DIR are honoured under WSL, exactly", { skip: WSL_NEEDS_POSIX_HOST }, async () => {
  // Exact assertions here: the override values are POSIX absolute paths and the
  // host resolves them the way a WSL distribution would, so the planned path can
  // be compared byte for byte.
  const claudeConfig = path.join(WSL_HOME, ".config", "claude-relocated");
  const codexHome = path.join(WSL_HOME, ".config", "codex-relocated");
  const context = wslContext({ CLAUDE_CONFIG_DIR: claudeConfig, CODEX_HOME: codexHome });

  const claude = await adapterById("claude-code").createInstallPlan(context, "global");
  const claudePaths = claude.writes.map((write) => write.path);
  assert.ok(
    claudePaths.includes(path.join(claudeConfig, "skills", "myrqen", "SKILL.md")),
    `the skill follows CLAUDE_CONFIG_DIR (got ${claudePaths.join(", ")})`
  );
  assert.ok(claudePaths.includes(path.join(claudeConfig, "CLAUDE.md")), "and so does the pointer");
  assert.ok(
    claudePaths.every((target) => !under(target, path.join(WSL_HOME, ".claude"))),
    "nothing is left in the default ~/.claude, which Claude Code would not read"
  );

  const codex = await adapterById("codex").createInstallPlan(context, "global");
  const codexPaths = codex.writes.map((write) => write.path);
  assert.ok(codexPaths.includes(path.join(codexHome, "AGENTS.md")), "the instructions file follows CODEX_HOME");
  assert.ok(
    codexPaths.every((target) => !under(target, path.join(WSL_HOME, ".codex"))),
    "nothing is left in the default ~/.codex"
  );
  // Documented asymmetry, asserted so a future "tidy-up" cannot erase it:
  // Codex searches for skills under $HOME/.agents, not under $CODEX_HOME.
  assert.ok(
    codexPaths.some((target) => under(target, path.join(WSL_HOME, ".agents", "skills"))),
    "the skill still goes to ~/.agents/skills, which is where Codex looks for it"
  );
});

test("CODEX_HOME and CLAUDE_CONFIG_DIR are honoured on win32", async () => {
  // Named rather than compared: both adapters run the override through
  // `path.resolve`, whose meaning belongs to the host, so a `C:\...` value
  // cannot be resolved faithfully anywhere but Windows. What is checkable
  // everywhere is the thing that actually breaks a user — an override that is
  // ignored, leaving the integration in a directory the agent never reads.
  const claudeConfig = path.win32.join(WINDOWS_HOME, "AppData", "Roaming", "claude-relocated");
  const codexHome = path.win32.join(WINDOWS_HOME, "AppData", "Roaming", "codex-relocated");
  const context = windowsContext({ CLAUDE_CONFIG_DIR: claudeConfig, CODEX_HOME: codexHome });

  const claude = await adapterById("claude-code").createInstallPlan(context, "global");
  assert.ok(
    claude.writes.every((write) => write.path.includes("claude-relocated")),
    "every global write follows CLAUDE_CONFIG_DIR"
  );
  assert.ok(
    claude.writes.every((write) => !under(write.path, path.win32.join(WINDOWS_HOME, ".claude"))),
    "and none is left in the default %USERPROFILE%\\.claude"
  );

  const codex = await adapterById("codex").createInstallPlan(context, "global");
  assert.ok(
    codex.writes.some((write) => write.path.includes("codex-relocated") && write.path.endsWith("AGENTS.md")),
    "the instructions file follows CODEX_HOME"
  );
  assert.ok(
    codex.writes.every((write) => !under(write.path, path.win32.join(WINDOWS_HOME, ".codex"))),
    "and nothing is left in the default %USERPROFILE%\\.codex"
  );
});

/* ---------- what the user is shown ---------- */

test("a Windows home is abbreviated with forward slashes and no drive letter", async () => {
  // Every path Myrqen prints goes through `displayPath`, and a plan that shows
  // `C:\Users\dev\...` puts the user's account name on their screen and in any
  // screenshot they send. Runnable off Windows because the home prefix cancels
  // out in the relative computation whatever the host's separator is; the
  // `path.sep`-to-slash conversion inside `displayPath` is the part only a
  // Windows host exercises.
  for (const row of await plannedWrites(windowsContext())) {
    const shown = row.write.displayPath;
    assert.ok(!shown.includes("\\"), `${describe(row)} was shown as ${shown}`);
    assert.ok(!/^[A-Za-z]:/.test(shown), `${describe(row)} showed a drive letter: ${shown}`);
    assert.ok(!shown.includes("Users/dev"), `${describe(row)} showed the account name: ${shown}`);
    if (!under(row.write.path, WINDOWS_REPO)) {
      assert.match(shown, /^~\//, `${describe(row)} is outside the repository and must read as ~/…`);
    }
  }

  // The same property asserted with the host's own separators, which is the
  // form that genuinely exercises `displayPath`'s `path.sep` handling when this
  // suite is run on Windows.
  const home = path.join(os.tmpdir(), "myrqen-display-home");
  const shown = displayPath(path.join(home, ".claude", "skills", "myrqen", "SKILL.md"), path.join(home, "repo"), home);
  assert.equal(shown, "~/.claude/skills/myrqen/SKILL.md");
});

/* ---------- what an adapter refuses ---------- */

test("every adapter claims Windows, and offers a user the same scopes there as on Linux", async () => {
  // If an adapter ever cannot support Windows, this is where it has to say so:
  // `platforms` is what `detectAll()` reads to skip it, and a plan is never
  // built for a platform the adapter does not list. Silently producing a broken
  // path instead is the failure this test exists to prevent.
  for (const adapter of ADAPTERS) {
    assert.ok(adapter.platforms.includes("win32"), `${adapter.id} does not list win32`);
    assert.deepEqual(
      adapter.supportedScopes(windowsContext()),
      adapter.supportedScopes(wslContext()),
      `${adapter.id} offers different scopes on Windows than on Linux without saying why`
    );
  }
});

test("a scope an adapter does not support produces an explanation, never a path", async () => {
  const context = windowsContext();

  const cursor = adapterById("cursor");
  assert.deepEqual(cursor.supportedScopes(context), ["project"]);
  const cursorGlobal = await cursor.createInstallPlan(context, "global");
  assert.deepEqual(cursorGlobal.writes, [], "Cursor's user rules live in the app, so there is nothing to write");
  assert.ok(cursorGlobal.notes.length > 0, "and the user is told that rather than left guessing");

  const agentsMd = adapterById("agents-md");
  assert.deepEqual(agentsMd.supportedScopes(context), ["project"]);
  const agentsGlobal = await agentsMd.createInstallPlan(context, "global");
  assert.ok(
    agentsGlobal.writes.every((write) => write.action === "blocked"),
    "AGENTS.md documents no user-level location, so the plan blocks instead of inventing one"
  );
});

/* ---------- CRLF, per adapter that writes a shared file ---------- */

const USER_MARKDOWN = ["# House rules", "", "Use tabs.", "Never touch legacy/.", ""].join("\r\n");
const USER_AIDER_CONFIG = ["# team settings", "read:", "  - CONVENTIONS.md", ""].join("\r\n");

/**
 * Every adapter that merges into a file somebody else owns, and the file it
 * merges into.
 *
 * A Windows developer's instruction files are CRLF, and an integration that
 * rewrites all of them to LF turns one small edit into a whole-file diff on
 * their next commit — the review noise lands on a colleague, and the tool that
 * promised to preserve their content is what caused it. `managed.ts` handles
 * this centrally; these cases prove each adapter actually goes through it.
 */
const SHARED_FILES = [
  { adapter: "claude-code", scope: "project", file: (home, repo) => path.join(repo, "CLAUDE.md"), seed: USER_MARKDOWN },
  { adapter: "agents-md", scope: "project", file: (home, repo) => path.join(repo, "AGENTS.md"), seed: USER_MARKDOWN },
  { adapter: "codex", scope: "global", file: (home) => path.join(home, ".codex", "AGENTS.md"), seed: USER_MARKDOWN },
  { adapter: "gemini-cli", scope: "project", file: (home, repo) => path.join(repo, "GEMINI.md"), seed: USER_MARKDOWN },
  {
    adapter: "windsurf",
    scope: "global",
    file: (home) => path.join(home, ".codeium", "windsurf", "memories", "global_rules.md"),
    seed: USER_MARKDOWN
  },
  { adapter: "cline", scope: "project", file: (home, repo) => path.join(repo, ".clinerules"), seed: USER_MARKDOWN },
  {
    adapter: "aider",
    scope: "project",
    file: (home, repo) => path.join(repo, ".aider.conf.yml"),
    seed: USER_AIDER_CONFIG,
    // Aider is the exception: when the user already keeps a `read:` key, Myrqen
    // adds one entry to it instead of fencing a region of its own, because a
    // second `read:` inside a marker would be a duplicate YAML key.
    evidence: /^ {2}- MYRQEN\.md$/m
  }
];

for (const shared of SHARED_FILES) {
  test(`${shared.adapter}: a CRLF ${path.basename(shared.file("", ""))} survives a merge on win32`, async () => {
    const base = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-crlf-"));
    try {
      const home = path.join(base, "home");
      const repoRoot = path.join(base, "repo");
      await fs.mkdir(home, { recursive: true });
      await fs.mkdir(repoRoot, { recursive: true });

      const target = shared.file(home, repoRoot);
      await fs.mkdir(path.dirname(target), { recursive: true });
      await fs.writeFile(target, shared.seed, "utf8");

      // Real directories, because the merge has to read the file back — but the
      // context still says win32, so any platform branch on the way to the merge
      // is the Windows one.
      const context = {
        repoRoot,
        home,
        skillSource: SKILL_SOURCE,
        platform: "win32",
        env: {}
      };

      const adapter = adapterById(shared.adapter);
      const plan = await adapter.createInstallPlan(context, shared.scope);
      const applied = await applyPlan(plan);
      assert.ok(applied.ok, `${shared.adapter} applied cleanly`);

      const after = await fs.readFile(target, "utf8");
      assert.ok(after.includes("\r\n"), "CRLF line endings survived");
      assert.ok(!/[^\r]\n/.test(after), "and not one line was left with a bare LF");
      assert.match(after, shared.evidence ?? /myrqen:start/, "Myrqen's own content is actually in the file");
      for (const line of shared.seed.split("\r\n").filter((entry) => entry.trim() !== "")) {
        assert.ok(after.includes(line), `the user's own line survived: ${line}`);
      }
    } finally {
      await fs.rm(base, { recursive: true, force: true });
    }
  });
}
