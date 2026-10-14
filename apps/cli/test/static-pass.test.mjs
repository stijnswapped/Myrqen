/**
 * The CLI's own detection path, end to end through the real binary.
 *
 * These tests run the published bundle against a throwaway project, because the
 * defect that matters is "a user installs Myrqen and it finds nothing" — which a
 * unit test on the analyser cannot catch. The project here is written from
 * scratch and shares no route, file name, or identifier with fixtures/, so a rule
 * keyed to a benchmark fixture would fail these.
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

const PROJECT = {
  "package.json": JSON.stringify({ name: "receipts-service", version: "1.0.0", type: "module" }, null, 2),
  "src/api.js": `
import fs from "node:fs";
import path from "node:path";

export async function handle(request, response) {
  const url = new URL(request.url, "http://localhost");
  const viewer = currentUser(request);

  if (request.method === "GET" && /^\\/api\\/receipts\\/\\d+$/.test(url.pathname)) {
    const identifier = url.pathname.split("/").pop();
    const receipt = await receipts.findOne({ id: identifier });
    return response.end(JSON.stringify(receipt));
  }

  if (request.method === "GET" && url.pathname === "/api/attachments") {
    const name = url.searchParams.get("name") ?? "";
    return response.end(fs.readFileSync(path.join("/srv/uploads", name), "utf8"));
  }

  return response.end("{}");
}

function currentUser(request) {
  return request.headers.authorization ? { id: 7 } : null;
}
`
};

async function makeProject() {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-cli-"));
  for (const [relativePath, contents] of Object.entries(PROJECT)) {
    const target = path.join(root, relativePath);
    await fs.mkdir(path.dirname(target), { recursive: true });
    await fs.writeFile(target, contents, "utf8");
  }
  return root;
}

async function cliJson(cwd, args) {
  const { stdout } = await run(process.execPath, [CLI, "--json", ...args], {
    cwd,
    env: { ...process.env, MYRQEN_TELEMETRY: "off" },
    maxBuffer: 32 * 1024 * 1024
  });
  return JSON.parse(stdout);
}

async function session(cwd) {
  const directory = path.join(cwd, ".myrqen", "sessions");
  const [id] = await fs.readdir(directory);
  return JSON.parse(await fs.readFile(path.join(directory, id, "session.json"), "utf8"));
}

test("a scan with no agent involvement still produces findings", async () => {
  const root = await makeProject();
  try {
    const context = await cliJson(root, ["auto", "--sync", "no"]);

    assert.ok(context.staticPass, "the session context must report what the static pass did");
    assert.ok(context.staticPass.candidatesRecorded >= 2, JSON.stringify(context.staticPass));
    assert.ok(context.staticPass.notAssessed.length >= 4, "the pass must state what it cannot see");

    const state = await session(root);
    const categories = state.findings.map((finding) => finding.category).sort();
    assert.ok(categories.includes("broken_object_level_authorization"), categories.join(", "));
    assert.ok(categories.includes("path_traversal"), categories.join(", "));

    const idor = state.findings.find((finding) => finding.category === "broken_object_level_authorization");
    assert.equal(idor.affected.route, "GET /api/receipts/:id", "the route is derived from the dispatch, not guessed");
    assert.equal(idor.verification, "needs_review", "static reading alone is never verified");
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("the static pass is idempotent: a second run corroborates rather than duplicates", async () => {
  const root = await makeProject();
  try {
    await cliJson(root, ["auto", "--sync", "no"]);
    const before = (await session(root)).findings.length;

    const again = await cliJson(root, ["session", "static-pass"]);
    assert.equal(again.created, 0, JSON.stringify(again));
    assert.equal(again.rejected, 0, JSON.stringify(again.rejections));
    assert.equal(again.merged, again.candidates);

    const after = (await session(root)).findings.length;
    assert.equal(after, before, "re-running must not grow the report");
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("an agent verifies a candidate instead of resubmitting it", async () => {
  const root = await makeProject();
  try {
    await cliJson(root, ["auto", "--sync", "no"]);
    const state = await session(root);
    const target = state.findings.find((finding) => finding.category === "broken_object_level_authorization");

    const result = await cliJson(root, [
      "finding",
      "verify",
      target.id,
      "--kind",
      "identity_differential",
      "--description",
      "Signed in as test user A and requested receipt 8102, which belongs to test user B; the response was HTTP 200 with user B's record.",
      "--location",
      "GET /api/receipts/8102"
    ]);
    assert.equal(result.verification, "verified");

    const after = await session(root);
    assert.equal(after.findings.length, state.findings.length, "verifying must not create a second finding");
    const verified = after.findings.find((finding) => finding.id === target.id);
    assert.equal(verified.verification, "verified");
    assert.equal(verified.corroboration.length, 1);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("a refuted candidate is kept, labelled, and carries the reason", async () => {
  const root = await makeProject();
  try {
    await cliJson(root, ["auto", "--sync", "no"]);
    const state = await session(root);
    const target = state.findings[0];

    await cliJson(root, [
      "finding",
      "refute",
      target.id,
      "--reason",
      "The lookup is scoped by session in middleware the static pass could not follow; the cross-account request returns 404."
    ]);

    const after = await session(root);
    const refuted = after.findings.find((finding) => finding.id === target.id);
    assert.equal(refuted.status, "false_positive");
    assert.match(refuted.corroboration.at(-1).description, /Could not reproduce/);
    assert.equal(after.findings.length, state.findings.length, "a refutation is recorded, never a deletion");
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("verifying requires an observation, not just a claim", async () => {
  const root = await makeProject();
  try {
    await cliJson(root, ["auto", "--sync", "no"]);
    const state = await session(root);
    // Under `--json` the reason is a JSON document on stdout, not prose on
    // stderr: a machine consumer parses stdout, and an empty stdout told it only
    // "Unexpected end of JSON input". The command still exits non-zero.
    let failure;
    try {
      await cliJson(root, ["finding", "verify", state.findings[0].id, "--description", "   "]);
    } catch (error) {
      failure = error;
    }
    assert.ok(failure, "the command failed");
    assert.notEqual(failure.code, 0, "a refused verification is not a success");
    const reported = JSON.parse(String(failure.stdout ?? "{}"));
    assert.match(reported.error?.message ?? "", /Verification needs a description/);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("a finding whose evidence quotes an environment dump survives redaction", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-env-"));
  try {
    await fs.mkdir(path.join(root, "src"), { recursive: true });
    await fs.writeFile(
      path.join(root, "package.json"),
      JSON.stringify({ name: "ops-console", version: "1.0.0", type: "module" }, null, 2)
    );
    await fs.writeFile(
      path.join(root, "src", "admin.js"),
      `export function handle(request, response) {
  const url = new URL(request.url, "http://localhost");
  if (url.pathname === "/internal/config") {
    return response.end(JSON.stringify({ PORT: process.env.PORT, SESSION_SECRET: process.env.SESSION_SECRET }));
  }
  return response.end("{}");
}
`,
      "utf8"
    );

    const context = await cliJson(root, ["auto", "--sync", "no"]);
    assert.equal(context.staticPass.candidatesRecorded > 0, true, JSON.stringify(context.staticPass));

    const state = await session(root);
    const serialised = JSON.stringify(state.findings);
    assert.ok(!/process\.env\.SESSION_SECRET["'\s]*[,}]?\s*\)/.test(serialised) || serialised.includes("REDACTED"), serialised);
    assert.ok(state.findings.length > 0, "a debug endpoint that dumps configuration must not vanish into redaction");
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("`finding list` returns the candidates the static pass recorded", async () => {
  /*
   * The gap this closes: `METHODOLOGY.md` opens the source-review phase with "start
   * by reading its candidates", and until this command existed nothing returned them.
   * `SessionContext.staticPass` carried a count, and `session static-pass` re-ran the
   * pass and resubmitted everything. An agent following the skill literally could not
   * see what there was to settle.
   */
  const cwd = await makeProject();
  const context = await cliJson(cwd, ["high"]);
  assert.ok(context.staticPass.candidatesRecorded > 0, "the static pass should find something in this project");

  const listed = await cliJson(cwd, ["finding", "list"]);
  const state = await session(cwd);

  // Exactly what the session holds, not a re-derivation of it.
  assert.equal(listed.total, state.findings.length);
  assert.deepEqual(
    listed.findings.map((finding) => finding.id).sort(),
    state.findings.map((finding) => finding.id).sort()
  );
  // Every row carries what an agent needs to go and exercise it.
  for (const finding of listed.findings) {
    assert.ok(finding.category, `${finding.id} should name its class`);
    assert.ok(finding.severity, `${finding.id} should carry a severity`);
    assert.ok(finding.affected, `${finding.id} should say what it affects`);
  }
});

test("listing candidates does not change the session", async () => {
  // `session static-pass` re-runs and resubmits, which inflates the duplicate
  // counter. Reading must be free, or an agent that reads twice corrupts its own
  // report.
  const cwd = await makeProject();
  await cliJson(cwd, ["high"]);
  const before = await session(cwd);
  await cliJson(cwd, ["finding", "list"]);
  await cliJson(cwd, ["finding", "list", "--all"]);
  const after = await session(cwd);

  assert.equal(after.findings.length, before.findings.length);
  assert.equal(after.candidateCount, before.candidateCount);
  assert.equal(after.duplicateCount, before.duplicateCount);
});

test("`finding list` hides settled findings unless asked", async () => {
  const cwd = await makeProject();
  await cliJson(cwd, ["high"]);
  const all = await cliJson(cwd, ["finding", "list", "--all"]);
  const target = all.findings[0];
  assert.ok(target, "the project should produce at least one candidate");

  await cliJson(cwd, ["finding", "refute", target.id, "--reason", "the path is a constant in this build"]);

  const unsettled = await cliJson(cwd, ["finding", "list"]);
  assert.ok(
    !unsettled.findings.some((finding) => finding.id === target.id),
    "a refuted finding is settled and should not be offered again"
  );
  const withSettled = await cliJson(cwd, ["finding", "list", "--all"]);
  assert.ok(withSettled.findings.some((finding) => finding.id === target.id), "--all should still show it");
});
