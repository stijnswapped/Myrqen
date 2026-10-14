import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { scan, routeFromFilePath } from "../dist/index.js";

/**
 * Every case here is written as source, not as a reference to a benchmark
 * fixture. A rule that only fires on a known fixture file is worthless in a real
 * repository, so the tests deliberately use different names, routes, and shapes
 * from anything in `fixtures/`.
 */
async function scanSource(files) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-scan-"));
  for (const [relativePath, contents] of Object.entries(files)) {
    const target = path.join(root, relativePath);
    await fs.mkdir(path.dirname(target), { recursive: true });
    await fs.writeFile(target, contents, "utf8");
  }
  try {
    return await scan({ repoRoot: root });
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
}

const categories = (result) => result.candidates.map((candidate) => candidate.category);
const routes = (result, category) =>
  result.candidates.filter((candidate) => candidate.category === category).map((candidate) => candidate.route);

test("a regular expression's exec method is not reported as a process spawn", async () => {
  const result = await scanSource({
    "src/cookies.js": `
      export function readSession(header) {
        const match = /(?:^|;\\s*)sid=([^;]+)/.exec(header);
        return match ? match[1] : null;
      }
    `
  });
  assert.deepEqual(
    categories(result).filter((category) => category === "command_injection"),
    [],
    "RegExp.prototype.exec collides with child_process.exec by name only"
  );
});

test("a shell command built from request data is still reported", async () => {
  const result = await scanSource({
    "src/convert.js": `
      import { exec } from "node:child_process";
      export function handler(req, res) {
        exec("convert " + req.query.file + " out.png", () => res.end("ok"));
      }
    `
  });
  assert.ok(categories(result).includes("command_injection"), "a bare exec() after a child_process import counts");
});

test("a fixed executable with fixed arguments is not reported", async () => {
  const result = await scanSource({
    "src/version.js": `
      import { execFile } from "node:child_process";
      export function handler(_req, res) {
        execFile("git", ["rev-parse", "HEAD"], (_error, out) => res.end(out));
      }
    `
  });
  assert.deepEqual(categories(result), [], "the safe decoy shape must stay silent");
});

test("regex-dispatched routes are discovered and used to attribute findings", async () => {
  const result = await scanSource({
    "src/router.js": `
      import { invoices } from "./store.js";
      export async function handle(request, response) {
        const url = new URL(request.url, "http://localhost");
        const viewer = currentUser(request);
        if (request.method === "GET" && /^\\/api\\/invoices\\/\\d+$/.test(url.pathname)) {
          const identifier = url.pathname.split("/").pop();
          const invoice = await invoices.findOne({ id: identifier });
          return response.end(JSON.stringify(invoice));
        }
        return response.end("{}");
      }
      function currentUser(request) {
        return request.headers.authorization ? { id: 1 } : null;
      }
    `
  });
  assert.deepEqual(
    routes(result, "broken_object_level_authorization"),
    ["GET /api/invoices/:id"],
    "the finding must be attributed to the regex-tested route, not to a neighbour"
  );
});

test("an ownership check on a neighbouring route does not suppress a finding", async () => {
  const result = await scanSource({
    "src/dispatch.js": `
      export async function handle(request, response) {
        const route = request.method + " " + new URL(request.url, "http://x").pathname;
        const user = currentUser(request);
        if (route === "GET /api/tickets/mine") {
          const ticket = await tickets.findOne({ id: request.headers["x-ticket"] });
          if (ticket.userId === user.id) return response.end("ok");
          return response.end("no");
        }
        if (route === "GET /api/documents/one") {
          const document = await documents.findOne({ id: request.headers["x-document"] });
          return response.end(JSON.stringify(document));
        }
        return response.end("{}");
      }
      function currentUser(request) { return { id: Number(request.headers["x-user"]) }; }
    `
  });
  const found = result.candidates.filter((candidate) => candidate.category === "broken_object_level_authorization");
  assert.equal(found.length, 1, "the unguarded lookup is still a finding");
  assert.match(found[0].evidence[0].snippet ?? "", /documents\.findOne/);
});

test("a defaulting operator does not break the taint chain", async () => {
  const result = await scanSource({
    "src/files.js": `
      import fs from "node:fs";
      import path from "node:path";
      export function handler(req, res) {
        const name = req.query.name ?? "";
        return res.end(fs.readFileSync(path.join("/srv/data", name), "utf8"));
      }
    `
  });
  assert.ok(categories(result).includes("path_traversal"), "`?? \"\"` keeps the value attacker controlled");
});

test("a value returned by a project helper stays tainted", async () => {
  const result = await scanSource({
    "src/import.js": `
      export async function handler(request, response) {
        const payload = await readBody(request);
        const fetched = await fetch(payload.endpoint);
        return response.end(String(fetched.status));
      }
      async function readBody(request) { return JSON.parse(await request.text()); }
    `
  });
  assert.ok(categories(result).includes("server_side_request_forgery"), "an unknown helper must not silently launder taint");
});

test("comparing one property to a literal does not clear the whole request", async () => {
  const result = await scanSource({
    "src/method.js": `
      import { exec } from "node:child_process";
      export function handler(request, response) {
        if (request.method !== "POST") { response.statusCode = 405; return response.end(); }
        exec("tar -xf " + request.body.archive, () => response.end("ok"));
      }
    `
  });
  assert.ok(
    categories(result).includes("command_injection"),
    "checking request.method says nothing about request.body"
  );
});

test("markup in a later argument position is still an HTML sink", async () => {
  const result = await scanSource({
    "src/page.js": `
      export function handler(req, res) {
        const term = req.query.q ?? "";
        return html(res, 200, "<h1>Results for " + term + "</h1>");
      }
      function html(res, status, body) { res.statusCode = status; res.end(body); }
    `
  });
  assert.ok(categories(result).includes("reflected_cross_site_scripting"));
});

test("escaped interpolation into markup is not reported", async () => {
  const result = await scanSource({
    "src/safe-page.js": `
      export function handler(req, res) {
        const term = escapeHtml(req.query.q ?? "");
        return res.send("<h1>Results for " + term + "</h1>");
      }
      function escapeHtml(value) {
        return String(value).replace(/[&<>"']/g, (character) => "&#" + character.charCodeAt(0) + ";");
      }
    `
  });
  assert.deepEqual(categories(result), []);
});

test("a self-describing fixture credential is not reported as a live secret", async () => {
  const result = await scanSource({
    "src/seed.js": `
      export const accounts = [
        { email: "a@example.com", password: "alice-password-1" },
        { email: "b@example.com", password: "bob-password-2" }
      ];
    `
  });
  assert.deepEqual(categories(result), [], "a real credential does not contain the word for what it is");
});

test("a shaped credential is reported without reproducing its value", async () => {
  const value = "sk_live_" + "9fJk2LmQ4rTz8vXb1nYc";
  const result = await scanSource({ "src/billing.js": `export const stripeKey = "${value}";\n` });
  const found = result.candidates.find((candidate) => candidate.category === "hardcoded_secret");
  assert.ok(found, "a Stripe live key shape must be reported");
  const serialised = JSON.stringify(found);
  assert.ok(!serialised.includes(value), "the report must never carry the credential it found");
});

test("query composition into an interpreted predicate is reported without SQL", async () => {
  const result = await scanSource({
    "src/search.js": `
      import { query } from "./store.js";
      export function handler(req, res) {
        const term = req.query.term ?? "";
        const where = "row.title.toLowerCase().includes(\\"" + term.toLowerCase() + "\\")";
        return res.end(JSON.stringify(query("articles", where)));
      }
    `
  });
  assert.ok(categories(result).includes("unsafe_query_composition"));
});

test("a parameterized SQL query is not reported", async () => {
  const result = await scanSource({
    "src/orders.js": `
      export async function handler(req, res, db) {
        const rows = await db.query("SELECT id, total FROM orders WHERE id = $1", [req.params.id]);
        return res.json(rows);
      }
    `
  });
  assert.deepEqual(categories(result), []);
});

test("a caller-controlled quantity that decides a total is reported", async () => {
  const result = await scanSource({
    "src/checkout.js": `
      export async function handler(request, response) {
        const viewer = currentUser(request);
        if (!viewer) return response.end("401");
        const payload = await readBody(request);
        const item = catalogue.find((candidate) => candidate.id === Number(payload.itemId));
        const units = Number(payload.units ?? 1);
        const amount = item.price * units;
        return response.end(JSON.stringify({ amount }));
      }
      async function readBody(request) { return JSON.parse(await request.text()); }
      function currentUser(request) { return request.headers.authorization ? { id: 1 } : null; }
    `
  });
  assert.ok(
    categories(result).includes("business_logic_price_manipulation"),
    "Number() removes the ability to inject text but not the caller's choice of value"
  );
});

test("a bounded quantity is not reported", async () => {
  const result = await scanSource({
    "src/safe-checkout.js": `
      export async function handler(request, response) {
        const viewer = currentUser(request);
        if (!viewer) return response.end("401");
        const payload = await readBody(request);
        const item = catalogue.find((candidate) => candidate.id === Number(payload.itemId));
        const units = Number(payload.units ?? 1);
        if (!Number.isInteger(units) || units < 1 || units > item.stock) return response.end("400");
        const amount = item.price * units;
        return response.end(JSON.stringify({ amount }));
      }
      async function readBody(request) { return JSON.parse(await request.text()); }
      function currentUser(request) { return request.headers.authorization ? { id: 1 } : null; }
    `
  });
  assert.ok(
    !categories(result).includes("business_logic_price_manipulation"),
    "an explicit range check is the fix, so the rule must go quiet"
  );
});

test("file-based route paths are derived from the file's location", () => {
  assert.equal(routeFromFilePath("app/api/orders/[id]/route.ts"), "/api/orders/:id");
  assert.equal(routeFromFilePath("apps/web/app/(marketing)/pricing/page.tsx"), "/pricing");
  assert.equal(routeFromFilePath("app/api/files/[...path]/route.js"), "/api/files/*");
  assert.equal(routeFromFilePath("src/lib/helper.ts"), null);
});

test("test and fixture files are excluded and the exclusion is disclosed", async () => {
  const result = await scanSource({
    "src/app.js": "export function handler(_req, res) { return res.end('ok'); }\n",
    "test/insecure.test.js": `
      import { exec } from "node:child_process";
      export function handler(req, res) { exec("rm -rf " + req.query.path, () => res.end("ok")); }
    `
  });
  assert.deepEqual(categories(result), [], "deliberately insecure test code is not the application's attack surface");
  assert.ok(
    result.coverage.notAssessed.some((statement) => /test, fixture, or example file/.test(statement)),
    "the skip must be stated rather than silent"
  );
});

test("coverage always states what the engine cannot see", async () => {
  const result = await scanSource({ "src/app.js": "export const value = 1;\n" });
  assert.ok(result.coverage.notAssessed.length >= 4);
  // The data-flow limit is stated: how far it reaches, and what it still does not connect.
  assert.ok(result.coverage.notAssessed.some((statement) => /across functions and modules/.test(statement) && /not connected/.test(statement)));
  assert.ok(result.coverage.rulesRun.length >= 19);
});
