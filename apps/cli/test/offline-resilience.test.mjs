/**
 * A linked device whose API cannot be reached must still get its whole scan.
 *
 * Scanning needs no network at all: discovery, the static pass, the findings and
 * every report format are local work. So the only honest behaviour when the API
 * refuses a connection is the behaviour an unlinked device already gets — the
 * scan stays local, and the CLI says so — rather than an exception out of
 * `session start` that leaves the user with an exit code and no report.
 *
 * This is a regression test for a defect that was unreachable only because
 * nothing was deployed yet: `myrqen link` mints its credential through the same
 * API, so nobody could be authenticated in the first place. Deploying is what
 * would have made it reachable, on the first scan of the first linked user.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const run = promisify(execFile);
const ROOT = path.resolve(import.meta.dirname, "..", "..", "..");
const CLI = path.join(ROOT, "apps", "cli", "dist", "myrqen.mjs");

/**
 * Port 9 is the discard service and is closed on every development machine, so
 * a request to it fails at connect rather than hanging. A test that waited for a
 * timeout would be a test nobody runs.
 */
const UNREACHABLE_API = "http://127.0.0.1:9";

const PROJECT = {
  "package.json": JSON.stringify({ name: "dispatch-board", version: "1.0.0", type: "module" }, null, 2),
  "src/dispatch.js": `
import fs from "node:fs";
import path from "node:path";

export async function handle(request, response) {
  const url = new URL(request.url, "http://localhost");
  const crew = currentCrew(request);

  if (request.method === "GET" && /^\\/api\\/consignments\\/\\d+$/.test(url.pathname)) {
    const reference = url.pathname.split("/").pop();
    const consignment = await consignments.findOne({ id: reference });
    return response.end(JSON.stringify(consignment));
  }

  if (request.method === "GET" && url.pathname === "/api/manifests") {
    const label = url.searchParams.get("label") ?? "";
    return response.end(fs.readFileSync(path.join("/srv/manifests", label), "utf8"));
  }

  return response.end("{}");
}

function currentCrew(request) {
  return request.headers.authorization ? { id: 41 } : null;
}
`
};

/**
 * A device that is linked as far as the CLI can tell: an account in the config
 * and a device token in the environment, which `readCredential` accepts as the
 * file backend. Nothing here touches the real keychain, and HOME is redirected
 * so nothing here can reach the developer's own agent configuration.
 */
async function makeLinkedDevice() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-offline-"));
  const project = path.join(root, "project");
  const configDirectory = path.join(root, "config");
  await fs.mkdir(configDirectory, { recursive: true });

  for (const [relativePath, contents] of Object.entries(PROJECT)) {
    const target = path.join(project, relativePath);
    await fs.mkdir(path.dirname(target), { recursive: true });
    await fs.writeFile(target, contents, "utf8");
  }

  await fs.writeFile(
    path.join(configDirectory, "config.json"),
    `${JSON.stringify(
      {
        version: 1,
        apiBaseUrl: UNREACHABLE_API,
        account: {
          userId: "usr_offline",
          email: "operator@example.test",
          deviceId: "dev_offline",
          deviceName: "test device",
          linkedAt: "2026-08-21T00:00:00.000Z",
          credentialBackend: "file"
        },
        telemetry: { enabled: false }
      },
      null,
      2
    )}\n`,
    "utf8"
  );

  return {
    root,
    project,
    env: {
      ...process.env,
      HOME: path.join(root, "home"),
      USERPROFILE: path.join(root, "home"),
      XDG_CONFIG_HOME: path.join(root, "home", ".config"),
      MYRQEN_CONFIG_DIR: configDirectory,
      MYRQEN_CREDENTIAL_BACKEND: "file",
      MYRQEN_DEVICE_TOKEN: "dvt_offline_regression_token",
      MYRQEN_API_BASE_URL: UNREACHABLE_API,
      MYRQEN_NON_INTERACTIVE: "1",
      MYRQEN_TELEMETRY: "off",
      NO_COLOR: "1"
    }
  };
}

async function cli(device, args) {
  return await run(process.execPath, [CLI, ...args], {
    cwd: device.project,
    env: device.env,
    maxBuffer: 32 * 1024 * 1024
  });
}

async function session(device) {
  const directory = path.join(device.project, ".myrqen", "sessions");
  const [id] = await fs.readdir(directory);
  return JSON.parse(await fs.readFile(path.join(directory, id, "session.json"), "utf8"));
}

test("a linked device whose API refuses connections still completes a local scan", async () => {
  const device = await makeLinkedDevice();
  try {
    const { stdout } = await cli(device, ["auto", "--sync", "no"]);

    const state = await session(device);
    assert.equal(state.project.bindingSource, "unbound", "an unreachable API must not leave a half-bound project");
    assert.equal(state.project.workspaceKind, "personal");
    assert.equal(state.project.workspaceId, undefined, "no workspace may be recorded when none could be read");

    assert.match(
      stdout,
      /The workspace list could not be read \(.+\), so this repository stays unbound and the scan stays local\./,
      `the reason must be named, not implied. Got:\n${stdout}`
    );
    assert.ok(state.findings.length > 0, "the static pass needs no network and must still produce findings");
  } finally {
    await fs.rm(device.root, { recursive: true, force: true });
  }
});

test("the local report is written even though the API was never reachable", async () => {
  const device = await makeLinkedDevice();
  try {
    await cli(device, ["auto", "--sync", "no"]);
    await cli(device, ["session", "finish"]);

    const state = await session(device);
    assert.equal(state.state, "complete");

    const directory = path.join(device.project, ".myrqen", "reports", state.localReportId);
    for (const file of ["report.json", "report.html", "report.md", "report.sarif.json"]) {
      const stat = await fs.stat(path.join(directory, file));
      assert.ok(stat.size > 0, `${file} must exist and carry content`);
    }

    const report = JSON.parse(await fs.readFile(path.join(directory, "report.json"), "utf8"));
    assert.ok(report.findings.length > 0, "a local report with no findings would hide the whole scan");
  } finally {
    await fs.rm(device.root, { recursive: true, force: true });
  }
});

test("an authenticated device with an existing binding degrades instead of throwing", async () => {
  const device = await makeLinkedDevice();
  try {
    // A committed team binding names a workspace the CLI cannot look up, which is
    // the shape a colleague's clone has: the binding is authoritative, only its
    // display name needs the API.
    await fs.mkdir(path.join(device.project, ".myrqen"), { recursive: true });
    await fs.writeFile(
      path.join(device.project, ".myrqen", "project.json"),
      `${JSON.stringify({ version: 1, kind: "team", workspaceId: "wsp_team", projectId: "prj_board" }, null, 2)}\n`,
      "utf8"
    );

    await cli(device, ["auto", "--sync", "no"]);
    const state = await session(device);
    assert.ok(state.findings.length > 0, "an unresolvable workspace name must not cost the scan");
  } finally {
    await fs.rm(device.root, { recursive: true, force: true });
  }
});
