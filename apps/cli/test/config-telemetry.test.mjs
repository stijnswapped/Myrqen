import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";

const run = promisify(execFile);
const CLI = path.resolve(import.meta.dirname, "..", "dist", "myrqen.mjs");

/**
 * The privacy page tells readers that `myrqen config telemetry off` turns product
 * analytics off. That sentence is only true if this passes.
 *
 * Before this command existed the setting was honoured but unreachable: the only
 * ways to change it were an environment variable on every invocation or editing
 * `config.json` by hand. These tests exist so that a refactor of the config
 * command cannot quietly take a privacy control away again.
 */
async function sandbox() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-telemetry-"));
  return {
    root,
    env: {
      ...process.env,
      HOME: root,
      USERPROFILE: root,
      XDG_CONFIG_HOME: path.join(root, ".config"),
      MYRQEN_CONFIG_DIR: path.join(root, "cfg"),
      MYRQEN_NON_INTERACTIVE: "1",
      NO_COLOR: "1",
      CI: "1"
    },
    configFile: path.join(root, "cfg", "config.json")
  };
}

test("config telemetry off persists the setting", async () => {
  const box = await sandbox();

  const { stdout } = await run(process.execPath, [CLI, "config", "telemetry", "off"], { env: box.env });
  assert.match(stdout, /Off/);

  const config = JSON.parse(await fs.readFile(box.configFile, "utf8"));
  assert.equal(config.telemetry.enabled, false);

  await fs.rm(box.root, { recursive: true, force: true });
});

test("config telemetry on turns it back on, and says what is sent", async () => {
  const box = await sandbox();

  await run(process.execPath, [CLI, "config", "telemetry", "off"], { env: box.env });
  const { stdout } = await run(process.execPath, [CLI, "config", "telemetry", "on"], { env: box.env });

  assert.match(stdout, /On/);
  // The reassurance is part of the contract: a user turning analytics back on
  // should be told what it is, not only that it happened.
  assert.match(stdout, /Never a file path, a finding, or a hostname/);

  const config = JSON.parse(await fs.readFile(box.configFile, "utf8"));
  assert.equal(config.telemetry.enabled, true);

  await fs.rm(box.root, { recursive: true, force: true });
});

test("an unrecognised value is refused rather than guessed at", async () => {
  const box = await sandbox();

  // "maybe" must not be read as falsy and silently disable analytics, and it must
  // not be read as truthy and silently enable them either.
  await assert.rejects(
    () => run(process.execPath, [CLI, "config", "telemetry", "maybe"], { env: box.env }),
    (error) => {
      assert.equal(error.code, 1);
      assert.match(`${error.stderr}${error.stdout}`, /Usage: config telemetry <on\|off>/);
      return true;
    }
  );

  // Nothing was written, so a typo cannot change a privacy setting.
  await assert.rejects(() => fs.readFile(box.configFile, "utf8"));

  await fs.rm(box.root, { recursive: true, force: true });
});

test("set-url still works, so adding a subcommand did not replace one", async () => {
  const box = await sandbox();

  await run(process.execPath, [CLI, "config", "set-url", "https://example.test:8443/ignored/path"], { env: box.env });

  const config = JSON.parse(await fs.readFile(box.configFile, "utf8"));
  // Only the origin is kept: a path in an API base URL would be appended to every
  // request that followed it.
  assert.equal(config.apiBaseUrl, "https://example.test:8443");

  await fs.rm(box.root, { recursive: true, force: true });
});
