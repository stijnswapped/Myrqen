/**
 * Verification is the agent's job. A run from a plain terminal must say so at the
 * start and at the end, name the exact way to continue in an agent this machine
 * has, and must not say any of it when an agent is driving.
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
const CLI = path.join(ROOT, "apps", "cli", "dist", "myrqen.mjs");
const host = await import(pathToFileURL(path.join(ROOT, "apps", "cli", "dist-tsc", "agent", "host.js")).href);

const AGENT_VARS = [
  "CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CLAUDE_CODE_SESSION_ID", "AI_AGENT", "AMP_CURRENT_THREAD_ID",
  "CODEX_THREAD_ID", "CODEX_SANDBOX", "CODEX_SANDBOX_NETWORK_DISABLED", "CODEX_CI",
  "OPENCODE", "OPENCODE_PID", "OPENCODE_CLIENT", "QWEN_CODE", "GEMINI_CLI",
  "CURSOR_AGENT", "CURSOR_SANDBOX", "CURSOR_EXTENSION_HOST_ROLE", "COPILOT_AGENT_SESSION_ID",
  "CLINE_ACTIVE", "ROO_ACTIVE", "MYRQEN_AGENT_NAME"
];

function cleanEnv(extra = {}) {
  const env = { ...process.env, MYRQEN_TELEMETRY: "off", MYRQEN_ASSUME_NO_ISOLATION: "1", HOME: os.tmpdir() };
  for (const key of AGENT_VARS) delete env[key];
  return { ...env, ...extra };
}

async function project() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-agent-"));
  await fs.writeFile(path.join(root, "package.json"), JSON.stringify({ name: "invoices", scripts: { start: "node server.js" } }));
  await fs.writeFile(
    path.join(root, "server.js"),
    `import http from "node:http";
import fs from "node:fs";
http.createServer((request, response) => {
  const url = new URL(request.url, "http://localhost");
  if (url.pathname === "/files") return response.end(fs.readFileSync("/srv/" + url.searchParams.get("name")));
  response.end("ok");
}).listen(4711);
`
  );
  return root;
}

test("host detection reads the hosts' own environment variables, nothing else", () => {
  assert.deepEqual(host.detectHostAgent({}), { detected: false });
  assert.equal(host.detectHostAgent({ CLAUDECODE: "1" }).name, "Claude Code");
  assert.equal(host.detectHostAgent({ AI_AGENT: "codex_1-2-3_agent" }).name, "Codex");
  assert.equal(host.detectHostAgent({ OPENCODE: "1" }).name, "OpenCode");
  assert.equal(host.detectHostAgent({ CODEX_THREAD_ID: "thr_1" }).name, "Codex");
  assert.equal(host.detectHostAgent({ CURSOR_EXTENSION_HOST_ROLE: "agent-exec" }).name, "Cursor");
  // Amp sets CLAUDECODE for compatibility; Qwen Code is a Gemini CLI fork.
  assert.equal(host.detectHostAgent({ AMP_CURRENT_THREAD_ID: "t", CLAUDECODE: "1" }).name, "Amp");
  assert.equal(host.detectHostAgent({ QWEN_CODE: "1", GEMINI_CLI: "1" }).name, "Qwen Code");
  assert.equal(host.detectHostAgent({ CLAUDECODE: "0" }).detected, false, '"0" is not a marker');
  assert.equal(host.detectHostAgent({}, "my-harness").source, "flag");
  assert.equal(host.detectHostAgent({}, "unknown").detected, false, '"unknown" is not a name');
});

test("hints follow the agents installed here, in their own syntax", () => {
  assert.deepEqual(host.verificationHints(["codex"], "auto"), ["$myrqen auto in a Codex session"]);
  assert.match(host.verificationHints([], "high")[0], /^\/myrqen high inside Claude Code$/);
  assert.equal(host.verificationHints([]).length, 3, "with nothing detected, the launch hosts are named");
  assert.equal(
    host.staticOnlySummary(9, ["/myrqen auto inside Claude Code"]),
    "Static pass only — 9 findings need proof. Run /myrqen auto inside Claude Code to verify them."
  );
});

test("a run with no agent says so at the start and at the end", async () => {
  const root = await project();
  try {
    const { stdout } = await run(process.execPath, [CLI, "auto", "--sync", "no"], { cwd: root, env: cleanEnv() });
    const lines = stdout.trim().split("\n");
    assert.match(lines[0], /^No coding agent detected\./, "the first line says what this run will not do");
    assert.match(lines.at(-1), /^Static pass only — \d+ findings? needs? proof\. Run .+ to verify/, lines.at(-1));
    assert.doesNotMatch(stdout, /\u001b\[/, "no escape codes in a pipe");
    assert.match(stdout, /^progress discover complete/m, "plain progress lines in a pipe");
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("a run inside an agent is not told to go and find one", async () => {
  const root = await project();
  try {
    const { stdout } = await run(process.execPath, [CLI, "auto", "--sync", "no"], {
      cwd: root,
      env: cleanEnv({ CLAUDECODE: "1" })
    });
    assert.doesNotMatch(stdout, /No coding agent detected|Static pass only/);
    assert.match(stdout, /Next steps for the host agent/);

    const { stdout: json } = await run(process.execPath, [CLI, "--json", "auto", "--sync", "no"], {
      cwd: root,
      env: cleanEnv({ CLAUDECODE: "1" })
    });
    const context = JSON.parse(json);
    assert.deepEqual(context.hostAgent, { detected: true, name: "Claude Code" });
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("--json stays a single JSON document with no progress lines", async () => {
  const root = await project();
  try {
    const { stdout } = await run(process.execPath, [CLI, "--json", "auto", "--sync", "no"], { cwd: root, env: cleanEnv() });
    const context = JSON.parse(stdout);
    assert.equal(context.hostAgent.detected, false);
    assert.equal(context.appRuntime.command, "npm start");
    assert.equal(context.appRuntime.port, 4711);
    assert.equal(context.appRuntime.persisted, false, "detected but not confirmed");
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});
