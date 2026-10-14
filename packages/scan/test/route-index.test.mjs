/**
 * Routes a handler file does not declare about itself.
 *
 * A handler module very often says nothing about the address it answers on: the
 * router is elsewhere. Before this existed, a correct finding on the correct line
 * carried no route, which cost the finding its address in the report and cost the
 * benchmark a match against ground truth that named one.
 *
 * These tests are written through the whole engine, on real multi-file projects
 * in a temporary directory, because the feature is about what one file learns
 * from another and a single-file test cannot exercise it.
 */
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

const dist = fileURLToPath(new URL("../dist/index.js", import.meta.url));

if (!existsSync(dist)) {
  test.skip("the route index needs a build: run `pnpm --filter @myrqen/scan build` first", () => {});
} else {
  const { scan } = await import(dist);

  /** Write a project out and scan it whole. */
  async function scanProject(files) {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-routeindex-"));
    try {
      for (const [relative, contents] of Object.entries(files)) {
        const target = path.join(root, relative);
        await fs.mkdir(path.dirname(target), { recursive: true });
        await fs.writeFile(target, contents, "utf8");
      }
      await fs.writeFile(
        path.join(root, "package.json"),
        `${JSON.stringify({ name: "case", version: "1.0.0", type: "module" }, null, 2)}\n`
      );
      return await scan({ repoRoot: root });
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  }

  const VULNERABLE_HANDLER = `
export async function listStatements(request, session, accountId) {
  const url = new URL(request.url);
  const merchant = url.searchParams.get("merchant") ?? "";
  const rows = await pool.query(
    "select id, amount from statements where account_id = $1 and merchant like '%" + merchant + "%'",
    [accountId]
  );
  return new Response(JSON.stringify(rows));
}
import { pool } from "./pool.js";
`;

  const routesOf = (result, category) =>
    result.candidates.filter((candidate) => candidate.category === category).map((candidate) => candidate.route);

  test("a pattern dispatcher lends its route to the handler it calls", async () => {
    const result = await scanProject({
      "handlers/statements.js": VULNERABLE_HANDLER,
      "pool.js": `export const pool = { query: async () => [] };`,
      "main.js": `
import { listStatements } from "./handlers/statements.js";

const STATEMENTS = new URLPattern({ pathname: "/accounts/:accountId/statements" });

Deno.serve(async (request) => {
  const statements = STATEMENTS.exec(request.url);
  if (statements && request.method === "GET") {
    return await listStatements(request, null, statements.pathname.groups.accountId);
  }
  return new Response("not found", { status: 404 });
});
`
    });

    assert.deepEqual(
      routesOf(result, "sql_injection"),
      ["GET /accounts/:accountId/statements"],
      "the route came from main.js, two bindings away from the literal"
    );
    assert.ok(
      result.coverage.notAssessed.some((line) => /different module/.test(line)),
      "the report says the route was borrowed from another module"
    );
  });

  test("a router registration lends its route to an imported controller", async () => {
    const result = await scanProject({
      "controllers/statements.js": VULNERABLE_HANDLER,
      "pool.js": `export const pool = { query: async () => [] };`,
      "routes.js": `
import { listStatements } from "./controllers/statements.js";
const router = makeRouter();
router.get("/billing/statements/:id", listStatements);
export default router;
`
    });
    assert.deepEqual(routesOf(result, "sql_injection"), ["GET /billing/statements/:id"]);
  });

  test("a routes table lends its route and its verb", async () => {
    const result = await scanProject({
      "handlers/statements.js": VULNERABLE_HANDLER,
      "pool.js": `export const pool = { query: async () => [] };`,
      "server.js": `
import { listStatements } from "./handlers/statements.js";
Bun.serve({ routes: { "/reports/:id/statements": { GET: listStatements } } });
`
    });
    assert.deepEqual(routesOf(result, "sql_injection"), ["GET /reports/:id/statements"]);
  });

  test("an import renamed at the call site is still keyed on what the other file exports", async () => {
    const result = await scanProject({
      "handlers/statements.js": VULNERABLE_HANDLER,
      "pool.js": `export const pool = { query: async () => [] };`,
      "routes.js": `
import { listStatements as statementsRoute } from "./handlers/statements.js";
const router = makeRouter();
router.get("/v2/statements", statementsRoute);
`
    });
    assert.deepEqual(routesOf(result, "sql_injection"), ["GET /v2/statements"]);
  });

  test("a handler registered twice under different paths is left unattributed", async () => {
    // Two addresses is not one address. Picking either would put the finding on
    // an endpoint it may not belong to, which is worse than admitting the gap.
    const result = await scanProject({
      "handlers/statements.js": VULNERABLE_HANDLER,
      "pool.js": `export const pool = { query: async () => [] };`,
      "routes.js": `
import { listStatements } from "./handlers/statements.js";
const router = makeRouter();
router.get("/accounts/:id/statements", listStatements);
router.get("/legacy/statements", listStatements);
`
    });
    assert.deepEqual(routesOf(result, "sql_injection"), [undefined]);
  });

  test("a same-named handler in another module never borrows the wrong route", async () => {
    // The index resolves the import to a path rather than matching on the name,
    // which is what keeps two handlers called `listStatements` apart.
    const result = await scanProject({
      "billing/statements.js": VULNERABLE_HANDLER,
      "reporting/statements.js": VULNERABLE_HANDLER,
      "pool.js": `export const pool = { query: async () => [] };`,
      "routes.js": `
import { listStatements } from "./billing/statements.js";
const router = makeRouter();
router.get("/billing/statements", listStatements);
`
    });
    const routes = routesOf(result, "sql_injection").sort((a, b) => String(a).localeCompare(String(b)));
    assert.deepEqual(
      routes,
      ["GET /billing/statements", undefined],
      "only the module the router actually imported gets the route"
    );
  });

  test("a route the file declares itself always wins over a borrowed one", async () => {
    const result = await scanProject({
      "handlers/statements.js": `
import { pool } from "../pool.js";
export async function listStatements(request) {
  const url = new URL(request.url);
  const merchant = url.searchParams.get("merchant") ?? "";
  return new Response(String(await pool.query("select * from s where m like '%" + merchant + "%'")));
}
const app = makeApp();
app.get("/declared-here", listStatements);
`,
      "pool.js": `export const pool = { query: async () => [] };`,
      "routes.js": `
import { listStatements } from "./handlers/statements.js";
const router = makeRouter();
router.get("/declared-elsewhere", listStatements);
`
    });
    assert.deepEqual(routesOf(result, "sql_injection"), ["GET /declared-here"]);
  });

  test("a bare package import is never resolved to a file in the scan", async () => {
    const result = await scanProject({
      "handlers/statements.js": VULNERABLE_HANDLER,
      "pool.js": `export const pool = { query: async () => [] };`,
      "routes.js": `
import { listStatements } from "some-published-package";
const router = makeRouter();
router.get("/not-ours", listStatements);
`
    });
    assert.deepEqual(
      routesOf(result, "sql_injection"),
      [undefined],
      "the local file was not registered, so it borrows nothing"
    );
  });
}
