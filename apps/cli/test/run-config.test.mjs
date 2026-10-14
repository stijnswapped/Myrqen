/**
 * First run: detect how to start the app, decide once, reuse silently. Names of
 * environment variables, never values; loopback addresses, never external ones.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { pathToFileURL } from "node:url";

const run = promisify(execFile);
const ROOT = path.resolve(import.meta.dirname, "..", "..", "..");
const CLI = path.join(ROOT, "apps", "cli", "dist", "myrqen.mjs");
const runtime = await import(pathToFileURL(path.join(ROOT, "apps", "cli", "dist-tsc", "discovery", "runtime.js")).href);
const projectConfig = await import(pathToFileURL(path.join(ROOT, "apps", "cli", "dist-tsc", "config", "project-config.js")).href);

const SECRET = "sk_live_runconfig_test_value_8f1c";

// Saving run settings records a confirmation in the machine-local config
// directory; keep that out of the developer's real one.
const CONFIG_DIR = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-runcfg-config-"));
process.on("exit", () => {
  try {
    rmSync(CONFIG_DIR, { recursive: true, force: true });
  } catch {
    // best effort
  }
});

function env() {
  const value = {
    ...process.env,
    MYRQEN_TELEMETRY: "off",
    MYRQEN_ASSUME_NO_ISOLATION: "1",
    MYRQEN_AGENT_NAME: "test-harness",
    MYRQEN_CONFIG_DIR: CONFIG_DIR
  };
  delete value.CLAUDECODE;
  delete value.AI_AGENT;
  return value;
}

async function makeProject(files) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-runcfg-"));
  for (const [relative, contents] of Object.entries(files)) {
    await fs.mkdir(path.dirname(path.join(root, relative)), { recursive: true });
    await fs.writeFile(path.join(root, relative), contents);
  }
  return root;
}

async function cli(cwd, args) {
  const { stdout } = await run(process.execPath, [CLI, ...args], { cwd, env: env() });
  return stdout;
}

test("a Next.js project: dev script, framework port, env names from the example only", async () => {
  const root = await makeProject({
    "package.json": JSON.stringify({ scripts: { dev: "next dev", start: "next start" }, dependencies: { next: "15.0.0" } }),
    "pnpm-lock.yaml": "lockfileVersion: 9\n",
    ".env.example": "# copy to .env\nDATABASE_URL=postgres://localhost/app\nexport STRIPE_SECRET_KEY=\nNEXT_PUBLIC_SITE=\n",
    ".env": `DATABASE_URL=postgres://real\nSTRIPE_SECRET_KEY=${SECRET}\nONLY_IN_DOTENV=1\n`
  });
  try {
    const detected = await runtime.detectRunConfig(root);
    assert.equal(detected.command, "pnpm dev");
    assert.equal(detected.port, 3000);
    assert.equal(detected.framework, "Next.js");
    assert.deepEqual(detected.env, ["DATABASE_URL", "STRIPE_SECRET_KEY", "NEXT_PUBLIC_SITE"]);
    assert.ok(!detected.env.includes("ONLY_IN_DOTENV"), ".env itself is never read");
    assert.doesNotMatch(JSON.stringify(detected), /sk_live|postgres:/, "no value survives detection");
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("a port named in the script beats the framework default", async () => {
  const root = await makeProject({
    "package.json": JSON.stringify({ scripts: { dev: "vite --port 5999" }, devDependencies: { vite: "6.0.0" } })
  });
  try {
    const detected = await runtime.detectRunConfig(root);
    assert.equal(detected.command, "npm run dev");
    assert.equal(detected.url, "http://127.0.0.1:5999");
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("nothing to start means no invented command", async () => {
  const root = await makeProject({ "package.json": JSON.stringify({ name: "library" }) });
  try {
    assert.equal(await runtime.detectRunConfig(root), null);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("the config refuses external addresses and values passed as names", () => {
  assert.throws(() => projectConfig.normalizeRunTarget("https://api.example.com"), /not a loopback address/);
  assert.throws(() => projectConfig.normalizeRunTarget("http://192.168.1.10:3000"), /not a loopback address/);
  assert.deepEqual(projectConfig.normalizeRunTarget("4010"), { url: "http://127.0.0.1:4010", port: 4010 });
  assert.throws(() => projectConfig.normalizeEnvNames([`API_KEY=${SECRET}`]), (error) => {
    assert.match(error.message, /looks like a value/);
    assert.doesNotMatch(error.message, new RegExp(SECRET), "the refusal does not echo the value");
    return true;
  });
});

test("flags persist the run config, and the next scan reuses it silently", async () => {
  const root = await makeProject({
    "package.json": JSON.stringify({ name: "shop", scripts: { start: "node server.js" } }),
    "server.js": "require('http').createServer((q, s) => s.end('ok')).listen(4790);\n"
  });
  try {
    const first = JSON.parse(
      await cli(root, ["--json", "auto", "--sync", "no", "--start-command", "npm run serve", "--app-url", "4791", "--app-env", "SESSION_SECRET,DATABASE_URL"])
    );
    assert.equal(first.appRuntime.command, "npm run serve");
    assert.equal(first.appRuntime.url, "http://127.0.0.1:4791");
    assert.equal(first.appRuntime.persisted, true);
    assert.ok(first.scope.discoveredLocalTargets.includes("http://127.0.0.1:4791"), "the configured app is a local target");

    const saved = JSON.parse(await fs.readFile(path.join(root, ".myrqen", "config.json"), "utf8"));
    assert.equal(saved.run.source, "flags");
    assert.deepEqual(saved.run.env, ["SESSION_SECRET", "DATABASE_URL"]);

    const second = JSON.parse(await cli(root, ["--json", "auto", "--sync", "no"]));
    assert.equal(second.appRuntime.command, "npm run serve", "reused, not re-detected");
    assert.ok(!second.nextSteps.some((step) => step.includes("detected, not confirmed")));
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("config shows, sets, and resets the project run settings", async () => {
  const root = await makeProject({
    "package.json": JSON.stringify({ name: "shop", scripts: { dev: "node server.js --port 4792" } })
  });
  try {
    let shown = JSON.parse(await cli(root, ["--json", "config"]));
    assert.equal(shown.project, null);

    await cli(root, ["config", "set", "run.command", "npm", "run", "dev"]);
    shown = JSON.parse(await cli(root, ["--json", "config"]));
    assert.equal(shown.project.run.command, "npm run dev");
    assert.equal(shown.project.run.url, "http://127.0.0.1:4792", "the unset part is filled from detection");

    await cli(root, ["config", "set", "run.url", "http://localhost:4793"]);
    await cli(root, ["config", "set", "run.env", "A_TOKEN,B_URL"]);
    shown = JSON.parse(await cli(root, ["--json", "config"]));
    assert.equal(shown.project.run.port, 4793);
    assert.deepEqual(shown.project.run.env, ["A_TOKEN", "B_URL"]);

    await assert.rejects(run(process.execPath, [CLI, "config", "set", "run.url", "https://evil.example"], { cwd: root, env: env() }), /not a loopback address/);

    await cli(root, ["config", "reset"]);
    shown = JSON.parse(await cli(root, ["--json", "config"]));
    assert.equal(shown.project.run, undefined);

    // The account-level subcommands still work beside the new ones.
    await assert.rejects(run(process.execPath, [CLI, "config", "bogus"], { cwd: root, env: env() }), /Usage/);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});
