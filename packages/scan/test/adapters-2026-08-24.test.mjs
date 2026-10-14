import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { scan } from "../dist/index.js";

/**
 * Four framework adapters, and the two guards they made necessary.
 *
 * Every source below is written from the framework's own documentation, not from any
 * corpus case, and named after nothing in one. The adapters exist because a held-out
 * corpus over AdonisJS, Convex, Effect, Hapi and Qwik produced **nothing at all** in
 * two thirds of its files: with no entry point there is no request parameter, with no
 * request parameter there is no taint, and every data-flow rule stays silent on a file
 * full of defects.
 *
 * The negatives matter more than the positives here. An adapter that claims a file it
 * should not seeds caller data into code no caller reaches, and the cost of that is
 * not one wrong finding but one per rule.
 */
async function scanFiles(files, pkg) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-adapters-"));
  await fs.writeFile(
    path.join(root, "package.json"),
    `${JSON.stringify({ name: "surface", private: true, type: "module", ...pkg }, null, 2)}\n`,
    "utf8"
  );
  for (const [relative, contents] of Object.entries(files)) {
    const target = path.join(root, relative);
    await fs.mkdir(path.dirname(target), { recursive: true });
    await fs.writeFile(target, contents, "utf8");
  }
  try {
    return await scan({ repoRoot: root });
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
}

/* --------------------------------------------------------------- AdonisJS v6 */

const ADONIS = { dependencies: { "@adonisjs/core": "^6.12.0", "@adonisjs/lucid": "^21.0.0" } };

test("an Adonis controller destructuring HttpContext is an entry point", async () => {
  const result = await scanFiles(
    {
      "app/controllers/statements_controller.ts": `
import type { HttpContext } from '@adonisjs/core/http'
import db from '@adonisjs/lucid/services/db'
export default class StatementsController {
  async show({ request, params, auth }: HttpContext) {
    const actor = auth.user!
    const sort = request.input('sort', 'issued_at')
    const rows = await db.rawQuery(\`select * from statements where ref = '\${params.reference}' order by \${sort}\`)
    return { actor: actor.id, rows }
  }
}
`
    },
    ADONIS
  );
  const found = result.candidates.filter((candidate) => candidate.category === "sql_injection");
  assert.equal(found.length, 1);
  // The verb and the path live in start/routes.ts, so the controller reports the only
  // address it can know. Guessing a URL would send a reader somewhere that does not exist.
  assert.equal(found[0].route, "StatementsController.show");
});

test("`db.rawQuery` is a SQL sink — the Adonis and Lucid spelling", async () => {
  // The list already carried `raw` and Prisma's `queryRaw`; nothing matched the words
  // the other way round, so an Adonis application had no SQL sink at all.
  const result = await scanFiles(
    {
      "app/controllers/rows_controller.ts": `
import type { HttpContext } from '@adonisjs/core/http'
import db from '@adonisjs/lucid/services/db'
export default class RowsController {
  async index({ request, auth }: HttpContext) {
    void auth.user
    return db.rawQuery(\`select * from rows where tag = '\${request.input('tag')}'\`)
  }
}
`
    },
    ADONIS
  );
  assert.equal(result.candidates.filter((candidate) => candidate.category === "sql_injection").length, 1);
});

test("`auth.user` is the authenticated subject, not the caller's", async () => {
  // The value a correctly scoped query is *supposed* to filter by. Seeding it would
  // make every properly written Adonis controller look like a broken one.
  const result = await scanFiles(
    {
      "app/controllers/scoped_controller.ts": `
import type { HttpContext } from '@adonisjs/core/http'
import db from '@adonisjs/lucid/services/db'
export default class ScopedController {
  async index({ auth }: HttpContext) {
    const actor = auth.user!
    return db.rawQuery(\`select * from invoices where org_id = '\${actor.organisationId}'\`)
  }
}
`
    },
    ADONIS
  );
  assert.deepEqual(result.candidates.map((candidate) => candidate.category), []);
});

/* -------------------------------------------------------------------- Convex */

const CONVEX = { dependencies: { convex: "^1.17.0" } };

test("a public Convex mutation is an entry point and its second argument is the caller's", async () => {
  const result = await scanFiles(
    {
      "convex/documents.ts": `
import { mutation } from "./_generated/server";
import { v } from "convex/values";
import { readFileSync } from "node:fs";
import { join } from "node:path";
export const readAttachment = mutation({
  args: { key: v.string() },
  handler: async (ctx, args) => {
    const actor = await ctx.auth.getUserIdentity();
    if (!actor) throw new Error("unauthenticated");
    return readFileSync(join("/srv/docs", args.key), "utf8");
  }
});
`
    },
    CONVEX
  );
  const found = result.candidates.filter((candidate) => candidate.category === "path_traversal");
  assert.equal(found.length, 1);
  // Convex functions are addressed by module and export, which is how a client calls one.
  assert.equal(found[0].route, "documents.readAttachment");
});

test("a Convex identity is not caller data", async () => {
  const result = await scanFiles(
    {
      "convex/scoped.ts": `
import { query } from "./_generated/server";
import { readFileSync } from "node:fs";
import { join } from "node:path";
export const own = query({
  args: {},
  handler: async (ctx) => {
    const actor = await ctx.auth.getUserIdentity();
    return readFileSync(join("/srv/docs", actor.subject), "utf8");
  }
});
`
    },
    CONVEX
  );
  assert.deepEqual(result.candidates.map((candidate) => candidate.category), []);
});

test("an httpAction takes its address from the router when the router is in the file", async () => {
  const result = await scanFiles(
    {
      "convex/http.ts": `
import { httpRouter } from "convex/server";
import { httpAction } from "./_generated/server";
import { readFileSync } from "node:fs";
import { join } from "node:path";
export const download = httpAction(async (ctx, request) => {
  void ctx;
  const key = new URL(request.url).searchParams.get("key");
  return new Response(readFileSync(join("/srv/docs", key), "utf8"));
});
const router = httpRouter();
router.route({ path: "/download", method: "GET", handler: download });
export default router;
`
    },
    CONVEX
  );
  const found = result.candidates.filter((candidate) => candidate.category === "path_traversal");
  assert.equal(found.length, 1);
  assert.equal(found[0].route, "GET /download");
});

/* --------------------------------------------------------------------- Hapi */

const HAPI = { dependencies: { "@hapi/hapi": "^21.3.0" } };
const HAPI_HEAD = `import { readFileSync } from 'node:fs';\nimport { join } from 'node:path';\nconst ROOT = '/srv/letters';\nexport const plugin = { name: 'letters', register(server) {\n`;
const HAPI_TAIL = `\n} };\n`;

async function hapiFindings(body) {
  const result = await scanFiles({ "lib/routes/letters.js": HAPI_HEAD + body + HAPI_TAIL }, HAPI);
  return result.candidates.filter((candidate) => candidate.category === "path_traversal");
}

test("a Hapi route object is an entry point, and its path parameter survives", async () => {
  // Reported as Hapi spells it. `{reference}` used to be stripped as though it were an
  // Express parameter *constraint*, which left `/api/letters/` — an address matching no
  // route and greppable for nothing.
  const found = await hapiFindings(`  server.route({
    method: 'GET',
    path: '/api/letters/{reference}',
    handler: (request, h) => h.response(readFileSync(join(ROOT, request.query.file), 'utf8'))
  });`);
  assert.equal(found.length, 1);
  assert.equal(found[0].route, "GET /api/letters/{reference}");
});

test("a Hapi handler nested under options is the same handler", async () => {
  const found = await hapiFindings(`  server.route({
    method: 'GET',
    path: '/api/notes/{noteId}',
    options: {
      auth: 'session',
      handler: (request, h) => h.response(readFileSync(join(ROOT, request.query.file), 'utf8'))
    }
  });`);
  assert.equal(found.length, 1);
  assert.equal(found[0].route, "GET /api/notes/{noteId}");
});

test("a route prerequisite is a handler, and carries the key it assigns", async () => {
  // `options.pre` is where real Hapi code loads the record, which makes it where a
  // missing ownership predicate lives. An adapter claiming only `handler` would leave
  // the most interesting function in the file unattributed.
  const found = await hapiFindings(`  server.route({
    method: 'GET',
    path: '/api/charts/{chartId}',
    options: {
      pre: [{ assign: 'chart', method: (request, h) => readFileSync(join(ROOT, request.query.file), 'utf8') }],
      handler: (request, h) => h.response(request.pre.chart)
    }
  });`);
  assert.equal(found.length, 1);
  assert.equal(found[0].route, "GET /api/charts/{chartId} (pre.chart)");
});

test("several verbs on one handler are reported as ANY rather than as the first", async () => {
  const found = await hapiFindings(`  server.route([{
    method: ['GET', 'HEAD'],
    path: '/api/scans/{scanId}',
    handler: (request, h) => h.response(readFileSync(join(ROOT, request.query.file), 'utf8'))
  }]);`);
  assert.equal(found.length, 1);
  assert.equal(found[0].route, "ANY /api/scans/{scanId}");
});

/* -------------------------------------------------------- Effect / platform */

const EFFECT = { dependencies: { effect: "^3.12.0", "@effect/platform": "^0.72.0", "@effect/sql": "^0.24.0" } };

test("an Effect handler is an entry point although it has no request parameter", async () => {
  // Three things defeat the generic model at once: the handler is an Effect rather than
  // a function of a request, the request arrives through a yielded accessor, and every
  // read sits behind a `yield*` — which the engine unwrapped for `await` and not for
  // `yield` until this landed.
  const result = await scanFiles(
    {
      "src/http/rate-sheets.ts": `
import { HttpRouter, HttpServerRequest } from "@effect/platform";
import { Effect, Schema } from "effect";
import { SqlClient } from "@effect/sql";
const Filters = Schema.Struct({ lane: Schema.String });
export const rateSheets = HttpRouter.get(
  "/api/rate-sheets/lines",
  Effect.gen(function* () {
    const sql = yield* SqlClient.SqlClient;
    const filters = yield* HttpServerRequest.schemaSearchParams(Filters);
    const statement = \`select * from rate_lines where lane = '\${filters.lane}'\`;
    return yield* sql.unsafe(statement);
  })
);
`
    },
    EFFECT
  );
  const found = result.candidates.filter((candidate) => candidate.category === "sql_injection");
  assert.equal(found.length, 1);
  assert.equal(found[0].route, "GET /api/rate-sheets/lines");
});

test("a bound Effect statement is silent", async () => {
  const result = await scanFiles(
    {
      "src/http/tariffs.ts": `
import { HttpRouter, HttpServerRequest } from "@effect/platform";
import { Effect, Schema } from "effect";
import { SqlClient } from "@effect/sql";
const Filters = Schema.Struct({ lane: Schema.String });
export const tariffs = HttpRouter.get(
  "/api/tariffs/lines",
  Effect.gen(function* () {
    const sql = yield* SqlClient.SqlClient;
    const filters = yield* HttpServerRequest.schemaSearchParams(Filters);
    return yield* sql\`select * from rate_lines where lane = \${filters.lane}\`;
  })
);
`
    },
    EFFECT
  );
  assert.deepEqual(result.candidates.map((candidate) => candidate.category), []);
});

test("a plain Effect.gen that is not a handler is not claimed", async () => {
  // A layer, a service constructor and a test are written the same way as a handler.
  // Seeding them would invent caller data in code no caller reaches.
  const result = await scanFiles(
    {
      "src/config.ts": `
import { Effect, Layer } from "effect";
import { readFileSync } from "node:fs";
import { join } from "node:path";
export const ConfigLive = Layer.effect(
  Symbol.for("Config"),
  Effect.gen(function* () {
    const name = process.env.CONFIG_NAME ?? "default";
    return readFileSync(join("/etc/app", name), "utf8");
  })
);
`
    },
    EFFECT
  );
  assert.deepEqual(result.candidates.map((candidate) => candidate.category), []);
});

/* ------------------------------------------- the allowlist in a conditional */

const EXPRESS = { dependencies: { express: "^4.19.0" } };

function rows(body) {
  return `import express from "express";\nconst ALLOWED = new Set(["a_col","b_col"]);\nconst r = express.Router();\nr.get("/rows", async (req, res) => {\n${body}\n});\nexport default r;\n`;
}

async function rowFindings(body) {
  const result = await scanFiles({ "src/rows.js": rows(body) }, EXPRESS);
  return result.candidates.filter((candidate) => candidate.category === "sql_injection");
}

test("an allowlist in a conditional expression is a guard", async () => {
  // `ALLOWED.has(x) ? x : "default"` is how a sort column is vetted in real code, and
  // the guard pass could not see it: it looks for a membership test inside an `if` whose
  // failing branch terminates, and a ternary has no branch to terminate. It is arguably
  // safer than the `if`/`return` form, because there is no way to fall through it.
  assert.equal((await rowFindings(`  const asked = String(req.query.sort ?? "a_col");
  const sort = ALLOWED.has(asked) ? asked : "a_col";
  return res.json(await db.query(\`select * from rows order by \${sort}\`));`)).length, 0);
});

test("the negated form is the same guard", async () => {
  assert.equal((await rowFindings(`  const asked = String(req.query.sort ?? "a_col");
  const sort = !ALLOWED.has(asked) ? "a_col" : asked;
  return res.json(await db.query(\`select * from rows order by \${sort}\`));`)).length, 0);
});

test("an array membership test counts too", async () => {
  assert.equal((await rowFindings(`  const asked = String(req.query.sort ?? "a_col");
  const sort = ["a_col","b_col"].includes(asked) ? asked : "a_col";
  return res.json(await db.query(\`select * from rows order by \${sort}\`));`)).length, 0);
});

test("a conditional that tests something other than membership is not a guard", async () => {
  assert.equal((await rowFindings(`  const asked = String(req.query.sort ?? "a_col");
  const sort = asked.length > 0 ? asked : "a_col";
  return res.json(await db.query(\`select * from rows order by \${sort}\`));`)).length, 1);
});

test("a fallback that is itself caller data is not a guard", async () => {
  assert.equal((await rowFindings(`  const asked = String(req.query.sort ?? "a_col");
  const sort = ALLOWED.has(asked) ? asked : String(req.query.other);
  return res.json(await db.query(\`select * from rows order by \${sort}\`));`)).length, 1);
});

test("testing one binding and using another is not a guard", async () => {
  assert.equal((await rowFindings(`  const asked = String(req.query.sort ?? "a_col");
  const other = String(req.query.dir);
  const sort = ALLOWED.has(asked) ? other : "a_col";
  return res.json(await db.query(\`select * from rows order by \${sort}\`));`)).length, 1);
});

/* ------------------------------- socket by shape ------------------------------ */

test("a per-event gateway module is claimed without any library token", async () => {
  /*
   * `applies` required the file to mention `socket.io`, `ws`, `WebSocketServer` or a
   * Socket.IO-only member. Real applications put one module per event —
   * `export function register(socket) { socket.on(...) }` — importing only its own
   * types and a database helper, with the io instance constructed elsewhere. Three
   * files of a held-out corpus were invisible for exactly that reason.
   */
  const result = await scanFiles(
    {
      "src/gateway/events/queue-filter.ts": `
import type { DeskSocket } from '../types.js';
import { pool } from '../../db/pool.js';
export function register(socket: DeskSocket) {
  socket.join('queue:' + socket.data.session.queueId);
  socket.on('queue:filter', async (payload, respond) => {
    const rows = await pool.query(\`select * from tickets where title like '%\${payload.term}%'\`);
    respond({ rows });
  });
}
`
    },
    { dependencies: { pg: "^8.13.0" } }
  );
  assert.equal(result.candidates.filter((candidate) => candidate.category === "sql_injection").length, 1);
});

test("a plain event emitter is not a socket", async () => {
  // `.on(...)` alone is an EventEmitter. Claiming it would seed caller data into
  // every queue consumer and internal bus in a codebase.
  const result = await scanFiles(
    {
      "src/bus/listener.ts": `
import { pool } from '../db/pool.js';
export function register(bus) {
  bus.on('tick', async (payload) => {
    await pool.query('select 1');
    void payload;
  });
}
`
    },
    { dependencies: { pg: "^8.13.0" } }
  );
  assert.deepEqual(result.candidates.map((candidate) => candidate.category), []);
});

/* --------------------------- a standalone Bun route table --------------------------- */

const BUN_TABLE = (statement) => `
import { sql } from "bun";
export const reportingRoutes = {
  "/api/wallets/:walletId/transactions": {
    GET: async (request) => {
      const url = new URL(request.url);
      const counterparty = url.searchParams.get("counterparty") ?? "";
      return Response.json({ rows: await ${statement} });
    }
  }
};
`;

test("a route table declared without a server still has an address", async () => {
  // `routes` was only read as a member of a `Bun.serve` configuration, so a table
  // living with the domain — which is how a Bun service of any size is written — gave
  // its handler no entry point and no route. The finding then landed at the right line
  // with `route: null`, which no scorer can match and no reader can act on.
  const result = await scanFiles(
    { "src/routes/transactions.js": BUN_TABLE("sql.unsafe(`select * from ledger where counterparty = '${counterparty}'`)") },
    {}
  );
  const found = result.candidates.filter((candidate) => candidate.category === "sql_injection");
  assert.equal(found.length, 1);
  assert.equal(found[0].route, "GET /api/wallets/:walletId/transactions");
});

test("the same table with a bound parameter is silent", async () => {
  const result = await scanFiles(
    { "src/routes/ledger.js": BUN_TABLE("sql`select * from ledger where counterparty = ${counterparty}`") },
    {}
  );
  assert.deepEqual(result.candidates.map((candidate) => candidate.category), []);
});

test("a path-keyed lookup table is not a route table", async () => {
  // An exported object with slash-shaped keys could be a map of anything. A route
  // table is one whose values are keyed by HTTP verb and hold functions.
  for (const source of [
    `export const LABELS = { "/api/a": "Alpha", "/api/b": "Beta" };\nexport function label(p) { return LABELS[p] ?? "unknown"; }\n`,
    `export const HELPERS = { "/api/a": () => 1, "/api/b": () => 2 };\nexport function pick(p) { return HELPERS[p]; }\n`
  ]) {
    const result = await scanFiles({ "src/routes/table.js": source }, {});
    assert.deepEqual(result.candidates.map((candidate) => candidate.category), []);
  }
});
