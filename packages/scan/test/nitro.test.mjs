import test from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import ts from "typescript";

/**
 * The Nitro / Nuxt / h3 adapter, driven directly rather than through `scan()`.
 *
 * Every case is written as source here. A framework adapter that only fires on a
 * fixture it has already seen is worthless in a real repository, and a test that
 * reads the corpus cannot tell the difference.
 *
 * Two things are asserted for every shape, because an entry point that gets one
 * of them wrong is worse than no entry point at all: the address a reader will
 * see in the report, and the seeds the taint model will trust.
 */
const here = path.dirname(fileURLToPath(import.meta.url));
const built = path.join(here, "../dist/ast/frameworks/nitro.js");

if (!existsSync(built)) {
  test.skip("the nitro adapter needs a build: dist/ast/frameworks/nitro.js is absent", () => {});
} else {
  const { nitroAdapter } = await import(pathToFileURL(built).href);

  const JAVASCRIPT = /\.[cm]?jsx?$/;

  function parsed(relativePath, text) {
    const scriptKind = JAVASCRIPT.test(relativePath) ? ts.ScriptKind.JS : ts.ScriptKind.TS;
    return {
      relativePath,
      absolutePath: `/repo/${relativePath}`,
      text,
      source: ts.createSourceFile(relativePath, text, ts.ScriptTarget.Latest, true, scriptKind),
      language: scriptKind === ts.ScriptKind.JS ? "JavaScript" : "TypeScript"
    };
  }

  /** What the engine would see: nothing at all unless the adapter claims the file. */
  function entriesOf(relativePath, text) {
    const file = parsed(relativePath, text);
    if (!nitroAdapter.applies(file)) return [];
    return nitroAdapter.detect(file);
  }

  const addresses = (entries) => entries.map((entry) => `${entry.method} ${entry.path}`);
  const seedNames = (entry) => (entry.seeds ?? []).map((seed) => seed.name);

  const HANDLER = `
    export default defineEventHandler(async (event) => {
      const query = getQuery(event);
      return { query };
    });
  `;

  /* -------------------------------------------------- addresses from the file tree */

  test("the method suffix and the api prefix come from the file name", () => {
    const found = entriesOf("server/api/members/search.post.ts", HANDLER);
    assert.deepEqual(addresses(found), ["POST /api/members/search"]);
  });

  test("a bracket segment is kept exactly as the developer wrote it", () => {
    const found = entriesOf("server/api/imports/[id]/status.get.ts", HANDLER);
    assert.deepEqual(addresses(found), ["GET /api/imports/[id]/status"]);
  });

  test("a route file with no method suffix answers any verb", () => {
    const found = entriesOf("server/api/health.ts", HANDLER);
    assert.deepEqual(addresses(found), ["ANY /api/health"]);
  });

  test("server/routes is served at the root, without the api prefix", () => {
    const found = entriesOf("server/routes/webhook.post.ts", HANDLER);
    assert.deepEqual(addresses(found), ["POST /webhook"]);
  });

  test("index addresses the directory it sits in rather than a segment of its own", () => {
    const found = entriesOf("server/api/orders/index.get.ts", HANDLER);
    assert.deepEqual(addresses(found), ["GET /api/orders"]);
  });

  test("middleware is reported as ANY / because every request passes through it", () => {
    const found = entriesOf("server/middleware/service-auth.ts", HANDLER);
    assert.deepEqual(addresses(found), ["ANY /"]);
  });

  test("the app's own server tree wins inside a monorepo path", () => {
    const found = entriesOf("apps/dashboard/server/api/members/search.post.ts", HANDLER);
    assert.deepEqual(addresses(found), ["POST /api/members/search"]);
  });

  /* -------------------------------------------------- the event, and how h3 delivers it */

  test("the single event parameter is seeded under its own name", () => {
    const [entry] = entriesOf("server/api/health.ts", HANDLER);
    assert.deepEqual(seedNames(entry), ["event"]);
    assert.equal(entry.seeds[0].origin, "event (inbound request)");
    assert.equal(entry.framework, "nitro");
    assert.equal(entry.kind, "http");
    assert.ok(entry.node, "the handler body is attached so taint has something to analyse");
  });

  test("a differently named event parameter is seeded under that name", () => {
    const [entry] = entriesOf(
      "server/api/health.ts",
      `export default defineEventHandler(async (e) => readBody(e));`
    );
    assert.deepEqual(seedNames(entry), ["e"]);
  });

  test("the h3 free functions are declared, because no property model can see them", () => {
    const [entry] = entriesOf("server/api/health.ts", HANDLER);
    for (const accessor of [
      "getQuery",
      "getRouterParam",
      "getRouterParams",
      "readBody",
      "readRawBody",
      "readValidatedBody",
      "readMultipartFormData",
      "readFormData",
      "getHeader",
      "getHeaders",
      "getRequestHeader",
      "getRequestHeaders",
      "getCookie",
      "getRequestURL",
      "getRequestPath",
      "getValidatedQuery",
      "getValidatedRouterParams"
    ]) {
      assert.ok(entry.accessorFunctions.includes(accessor), `${accessor} must be an accessor`);
    }
  });

  test("server-derived readers are not accessors, or every scoped query would be a finding", () => {
    const [entry] = entriesOf("server/api/health.ts", HANDLER);
    for (const trusted of ["getRequestIP", "useSession", "getSession", "requireUserSession"]) {
      assert.ok(!entry.accessorFunctions.includes(trusted), `${trusted} must not be an accessor`);
    }
  });

  test("each entry point gets its own accessor list rather than a shared one", () => {
    const first = entriesOf("server/api/health.ts", HANDLER)[0];
    const second = entriesOf("server/api/other.ts", HANDLER)[0];
    assert.notEqual(first.accessorFunctions, second.accessorFunctions);
  });

  /* -------------------------------------------------- the shapes a handler is written in */

  test("the options object form is read through its handler property", () => {
    const [entry] = entriesOf(
      "server/api/members/search.post.ts",
      `
        export default defineEventHandler({
          onRequest: [logRequest],
          handler: async (event) => readBody(event)
        });
      `
    );
    assert.deepEqual(addresses([entry]), ["POST /api/members/search"]);
    assert.deepEqual(seedNames(entry), ["event"]);
  });

  test("a handler declared as a named function in the same file is resolved", () => {
    const [entry] = entriesOf(
      "server/api/members/search.post.ts",
      `
        async function handleSearch(event) {
          return readBody(event);
        }
        export default defineEventHandler(handleSearch);
      `
    );
    assert.deepEqual(seedNames(entry), ["event"]);
    assert.ok(ts.isFunctionDeclaration(entry.node));
  });

  test("the eventHandler alias is the same framework", () => {
    const found = entriesOf("server/routes/webhook.post.ts", `export default eventHandler((event) => readBody(event));`);
    assert.deepEqual(addresses(found), ["POST /webhook"]);
    assert.deepEqual(seedNames(found[0]), ["event"]);
  });

  test("a cached handler is exactly as reachable as an uncached one", () => {
    const found = entriesOf(
      "server/api/reports.get.ts",
      `export default defineCachedEventHandler(async (event) => getQuery(event), { maxAge: 60 });`
    );
    assert.deepEqual(addresses(found), ["GET /api/reports"]);
    assert.deepEqual(seedNames(found[0]), ["event"]);
  });

  test("a bare exported function is a route too", () => {
    const found = entriesOf(
      "server/api/members/search.post.ts",
      `export default async (event) => { const body = await readBody(event); return body; };`
    );
    assert.deepEqual(addresses(found), ["POST /api/members/search"]);
    assert.deepEqual(seedNames(found[0]), ["event"]);
  });

  test("a bare export typed as an H3Event is seeded whatever the parameter is called", () => {
    const found = entriesOf(
      "server/api/members/search.post.ts",
      `
        import type { H3Event } from "h3";
        export default async function handle(ctx: H3Event) {
          return readBody(ctx);
        }
      `
    );
    assert.deepEqual(seedNames(found[0]), ["ctx"]);
  });

  test("a CommonJS handler in a JavaScript file is recognised", () => {
    const found = entriesOf(
      "server/api/webhooks/stripe.post.js",
      `
        const { defineEventHandler, readBody } = require("h3");
        module.exports = defineEventHandler(async (event) => {
          const body = await readBody(event);
          return { ok: true, body };
        });
      `
    );
    assert.deepEqual(addresses(found), ["POST /api/webhooks/stripe"]);
    assert.deepEqual(seedNames(found[0]), ["event"]);
  });

  /* -------------------------------------------------- h3 outside the file-based convention */

  test("a handler outside a server tree still seeds, at an unplaced address", () => {
    const found = entriesOf(
      "src/handlers/search.ts",
      `export const search = defineEventHandler(async (event) => getQuery(event));`
    );
    assert.deepEqual(addresses(found), ["ANY /"]);
    assert.deepEqual(seedNames(found[0]), ["event"]);
  });

  test("an h3 router mount supplies the address the file name cannot", () => {
    const found = entriesOf(
      "src/server.ts",
      `
        import { createRouter, defineEventHandler, getRouterParam } from "h3";
        const router = createRouter();
        router.get("/orders/:id", defineEventHandler((event) => getRouterParam(event, "id")));
      `
    );
    assert.deepEqual(addresses(found), ["GET /orders/:id"]);
    assert.deepEqual(seedNames(found[0]), ["event"]);
  });

  /* -------------------------------------------------- what the adapter refuses to claim */

  test("a helper module inside the server tree is not a route", () => {
    const file = parsed(
      "server/utils/db.ts",
      `
        import { createPool } from "mysql2/promise";
        export const pool = createPool({ uri: process.env.DATABASE_URL });
        export default pool;
      `
    );
    assert.equal(nitroAdapter.applies(file), false);
  });

  test("an unrelated file that merely mentions h3 in prose is not claimed", () => {
    const file = parsed("src/notes.ts", `// we should migrate this to an eventHandler one day\nexport const notes = 1;`);
    assert.equal(nitroAdapter.applies(file), false);
  });

  test("an identifier that ends in EventHandler is not a handler wrapper", () => {
    const file = parsed("src/ui.ts", `export function attach(onEventHandler: () => void) { onEventHandler(); }`);
    assert.equal(nitroAdapter.applies(file), false);
  });

  test("a plain factory under server/api gets the address and no seeds", () => {
    const found = entriesOf(
      "server/api/client.ts",
      `export default function createClient(options) { return { options }; }`
    );
    assert.deepEqual(addresses(found), ["ANY /api/client"]);
    assert.equal(found[0].seeds, undefined, "a guessed seed would flag configuration as attacker data");
    assert.equal(found[0].accessorFunctions, undefined);
  });

  test("a default export that is not a function yields nothing", () => {
    const found = entriesOf("server/api/config.ts", `export default { retries: 3 };`);
    assert.deepEqual(found, []);
  });

  test("a lazy handler is left alone rather than seeded through its factory", () => {
    const found = entriesOf(
      "server/api/reports.get.ts",
      `export default defineLazyEventHandler(async () => defineEventHandler((event) => getQuery(event)));`
    );
    // The inner handler is the real one; the factory contributes no seeds of its own.
    assert.deepEqual(addresses(found), ["GET /api/reports"]);
    assert.deepEqual(seedNames(found[0]), ["event"]);
  });

  test("a destructured parameter is not guessed at", () => {
    const [entry] = entriesOf(
      "server/api/health.ts",
      `export default defineEventHandler(async ({ context }) => context.user);`
    );
    assert.equal(entry.seeds, undefined);
    assert.deepEqual(addresses([entry]), ["ANY /api/health"]);
  });
}
