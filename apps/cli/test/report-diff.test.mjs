/**
 * `report` and `diff`: find the latest report without hunting through
 * .myrqen/reports, and say what changed between two runs by stable identity.
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
const { compareRuns, locationFingerprinter } = await import(pathToFileURL(path.join(ROOT, "apps", "cli", "dist-tsc", "history", "compare.js")).href);

function env() {
  const value = { ...process.env, MYRQEN_TELEMETRY: "off", MYRQEN_ASSUME_NO_ISOLATION: "1", MYRQEN_AGENT_NAME: "test-harness" };
  delete value.CLAUDECODE;
  delete value.AI_AGENT;
  return value;
}

async function cli(cwd, args) {
  const { stdout } = await run(process.execPath, [CLI, ...args], { cwd, env: env(), maxBuffer: 32 * 1024 * 1024 });
  return stdout;
}

function f(fingerprint, status = "open", extra = {}) {
  return {
    id: `MYR-${fingerprint}`,
    fingerprint,
    title: `finding ${fingerprint}`,
    severity: "high",
    verification: "needs_review",
    status,
    ...extra
  };
}

test("findings are classified new, fixed, still open, and regressed by fingerprint", () => {
  const base = [f("a"), f("b"), f("c", "fixed_verified"), f("d", "false_positive"), f("h", "fixed_verified")];
  const head = [f("a"), f("c"), f("e"), f("b", "fixed_verified"), f("g")];
  const history = [[f("g", "fixed_verified")]];
  const byField = { fingerprint: (finding) => finding.fingerprint };
  const diff = compareRuns(base, head, { history, fingerprinter: byField });

  assert.deepEqual(diff.stillOpen.map((entry) => entry.fingerprint), ["a"]);
  assert.deepEqual(diff.new.map((entry) => entry.fingerprint), ["e"]);
  assert.deepEqual(diff.regressed.map((entry) => entry.fingerprint).sort(), ["c", "g"], "a fix that came back is a regression");
  assert.deepEqual(diff.fixed.map((entry) => entry.fingerprint), ["b", "h"], "fixed by the loop after base, and gone now");
  assert.equal(diff.fixed[0].reason, "fixed_and_verified");
  assert.equal(diff.fixed[1].reason, "no_longer_reported");

  const gone = compareRuns([f("x")], [], { fingerprinter: byField });
  assert.equal(gone.fixed[0].reason, "no_longer_reported");
  assert.equal(compareRuns([f("x", "false_positive")], [], { fingerprinter: byField }).fixed.length, 0, "a refuted finding was never open");
});

test("cross-run identity ignores reworded summaries and moved lines, and keeps same-place findings apart", () => {
  const ssrf = (summary, line, id = "MYR-007") => ({
    id,
    category: "ssrf",
    title: "Server issues a request to a caller-influenced destination",
    severity: "high",
    verification: "needs_review",
    status: "open",
    summary,
    tags: ["static-pass", "outbound-request-forgery"],
    affected: { component: "src/server.js", file: "src/server.js", lineStart: line, route: "POST /api/import/12" }
  });
  const before = ssrf("The destination given to fetch is derived from url.searchParams.get().", 139);
  const after = ssrf("The destination given to fetch is derived from url.searchParams.get() via path.basename().", 141, "MYR-009");
  assert.equal(locationFingerprinter.fingerprint(before), locationFingerprinter.fingerprint(after));
  const diff = compareRuns([before], [after]);
  assert.equal(diff.stillOpen.length, 1, JSON.stringify(diff));
  assert.equal(diff.new.length + diff.fixed.length, 0);

  const twin = ssrf("A second request in the same handler.", 150, "MYR-010");
  const both = compareRuns([before], [after, twin]);
  assert.equal(both.stillOpen.length, 1);
  assert.equal(both.new.length, 1, "two findings in one place are two findings");
});

const VULNERABLE = `import fs from "node:fs";
import path from "node:path";
import { exec } from "node:child_process";
export async function handle(request, response) {
  const url = new URL(request.url, "http://localhost");
  if (url.pathname === "/api/attachments") {
    const name = url.searchParams.get("name") ?? "";
    return response.end(fs.readFileSync(path.join("/srv/uploads", name), "utf8"));
  }
  if (url.pathname === "/api/convert") {
    const file = url.searchParams.get("file");
    exec("convert " + file + " out.png");
    return response.end("queued");
  }
  return response.end("{}");
}
`;

const PATCHED = VULNERABLE.replace(
  `return response.end(fs.readFileSync(path.join("/srv/uploads", name), "utf8"));`,
  `return response.end(fs.readFileSync(path.join("/srv/uploads", path.basename(name)), "utf8"));`
);

test("report opens nothing in a pipe, prints paths, lists runs; diff compares the last two", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-report-"));
  try {
    await fs.writeFile(path.join(root, "package.json"), JSON.stringify({ name: "attachments", type: "module" }));
    await fs.mkdir(path.join(root, "src"));
    await fs.writeFile(path.join(root, "src", "api.js"), VULNERABLE);

    await assert.rejects(run(process.execPath, [CLI, "report"], { cwd: root, env: env() }), /No runs/);

    await cli(root, ["--json", "auto", "--sync", "no"]);
    await assert.rejects(run(process.execPath, [CLI, "report"], { cwd: root, env: env() }), /No run has been finished/);
    await cli(root, ["--json", "session", "finish"]);

    const html = (await cli(root, ["report"])).trim();
    assert.match(html, /\.myrqen[\\/]reports[\\/]rpt_[^\\/]+[\\/]report\.html$/, "a pipe gets the path, not a browser");
    const sarif = JSON.parse(await cli(root, ["--json", "report", "--format", "sarif"]));
    assert.match(sarif.path, /report\.sarif\.json$/);
    await fs.access(sarif.path);
    await assert.rejects(run(process.execPath, [CLI, "report", "--format", "pdf"], { cwd: root, env: env() }), /--format must be one of/);

    await fs.writeFile(path.join(root, "src", "api.js"), PATCHED);
    await cli(root, ["--json", "auto", "--sync", "no"]);
    await cli(root, ["--json", "session", "finish"]);

    const listed = JSON.parse(await cli(root, ["--json", "report", "--last", "5"]));
    assert.equal(listed.runs.length, 2);
    assert.ok(listed.runs.every((entry) => entry.hasReport));
    assert.ok(listed.runs[1].open > listed.runs[0].open, "the newer run has fewer open findings");

    const diff = JSON.parse(await cli(root, ["--json", "diff"]));
    assert.equal(diff.counts.new, 0, JSON.stringify(diff.new));
    assert.equal(diff.counts.regressed, 0);
    assert.ok(diff.counts.fixed >= 1, "the traversal is gone");
    assert.ok(diff.fixed.some((entry) => /travers|path/i.test(entry.title)), JSON.stringify(diff.fixed));
    assert.ok(diff.counts.stillOpen >= 1, "the command injection is still there");

    // Reversed, the fix reads as new: the comparison is directional.
    const reversed = JSON.parse(await cli(root, ["--json", "diff", "1", "2"]));
    assert.equal(reversed.counts.new, diff.counts.fixed);

    const text = await cli(root, ["diff"]);
    assert.match(text, /^Fixed \(\d+\)/m);
    assert.match(text, /^Still open \(\d+\)/m);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});
