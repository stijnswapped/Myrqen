import test from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import ts from "typescript";

/**
 * The TanStack Start / SolidStart adapter, driven directly rather than through
 * `scan()`.
 *
 * Every case is written as source here. A framework adapter that only fires on a
 * fixture it has already seen is worthless in a real repository, and a test that
 * reads the corpus cannot tell the difference.
 *
 * Two things are asserted for every shape, because an entry point that gets one
 * of them wrong is worse than no entry point at all: the address a reader will
 * see in the report, and the seeds the taint model will trust. Each shape is
 * followed by the near miss it must not claim, since a wrong seed here invents
 * flows across every data-flow rule in the engine at once.
 */
const here = path.dirname(fileURLToPath(import.meta.url));
const built = path.join(here, "../dist/ast/frameworks/tanstack-solid.js");

if (!existsSync(built)) {
  test.skip("the tanstack-solid adapter needs a build: dist/ast/frameworks/tanstack-solid.js is absent", () => {});
} else {
  const { tanstackSolidAdapter } = await import(pathToFileURL(built).href);

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
    if (!tanstackSolidAdapter.applies(file)) return [];
    return tanstackSolidAdapter.detect(file);
  }

  const addresses = (entries) => entries.map((entry) => `${entry.method} ${entry.path}`);
  const seedNames = (entry) => (entry.seeds ?? []).map((seed) => seed.name);

  /* ---------------------------------------------- TanStack Start server functions */

  const TANSTACK_IMPORT = `import { createServerFn } from "@tanstack/react-start";`;

  test("a server function is addressed by the name the client imports", () => {
    const found = entriesOf(
      "app/server/orders.ts",
      `
        ${TANSTACK_IMPORT}
        export const approveOrder = createServerFn({ method: "POST" })
          .validator((input: unknown) => schema.parse(input))
          .handler(async ({ data }) => {
            return db.order.update({ where: { id: data.id }, data: { status: "approved" } });
          });
      `
    );
    assert.deepEqual(addresses(found), ["POST approveOrder"]);
    assert.deepEqual(seedNames(found[0]), ["data"]);
    assert.equal(found[0].seeds[0].origin, "data (caller-supplied server-function input)");
    assert.equal(found[0].framework, "tanstack-start");
    assert.equal(found[0].kind, "action");
    assert.ok(found[0].node, "the handler body is attached so taint has something to analyse");
  });

  test("the older @tanstack/start package name is the same framework", () => {
    const found = entriesOf(
      "app/server/orders.ts",
      `
        import { createServerFn } from "@tanstack/start";
        export const approveOrder = createServerFn({ method: "POST" }).handler(async ({ data }) => data);
      `
    );
    assert.deepEqual(addresses(found), ["POST approveOrder"]);
    assert.deepEqual(seedNames(found[0]), ["data"]);
  });

  test("the declared method wins over the default", () => {
    const found = entriesOf(
      "app/server/orders.ts",
      `
        ${TANSTACK_IMPORT}
        export const listOrders = createServerFn({ method: "GET" }).handler(async ({ data }) => data);
      `
    );
    assert.deepEqual(addresses(found), ["GET listOrders"]);
  });

  test("a server function with no options is the POST the client sends", () => {
    const found = entriesOf(
      "app/server/orders.ts",
      `
        ${TANSTACK_IMPORT}
        export const saveNote = createServerFn().handler(async ({ data }) => data);
      `
    );
    assert.deepEqual(addresses(found), ["POST saveNote"]);
  });

  test("the middleware's context is declared trusted, because it is not the caller's", () => {
    const [entry] = entriesOf(
      "app/server/orders.ts",
      `
        ${TANSTACK_IMPORT}
        export const approveOrder = createServerFn()
          .middleware([authed])
          .handler(async ({ data, context }) => db.order.update({ where: { id: context.tenantId }, data }));
      `
    );
    assert.deepEqual(seedNames(entry), ["data"]);
    assert.deepEqual(entry.trustedParameters, ["context"]);
  });

  test("a renamed binding is seeded under the name it actually binds", () => {
    const [entry] = entriesOf(
      "app/server/orders.ts",
      `
        ${TANSTACK_IMPORT}
        export const approveOrder = createServerFn().handler(async ({ data: payload }) => payload);
      `
    );
    assert.deepEqual(seedNames(entry), ["payload"]);
  });

  test("a handler that takes the whole bag gets the address and no seeds", () => {
    const [entry] = entriesOf(
      "app/server/orders.ts",
      `
        ${TANSTACK_IMPORT}
        export const approveOrder = createServerFn().handler(async (ctx) => db.order.update(ctx.data));
      `
    );
    assert.deepEqual(addresses([entry]), ["POST approveOrder"]);
    assert.equal(entry.seeds, undefined, "seeding the bag would mark the middleware's own context as caller data");
  });

  test("a handler declared as a named function in the same file is resolved", () => {
    const [entry] = entriesOf(
      "app/server/orders.ts",
      `
        ${TANSTACK_IMPORT}
        async function approve({ data }) {
          return db.order.update({ where: { id: data.id } });
        }
        export const approveOrder = createServerFn().handler(approve);
      `
    );
    assert.deepEqual(seedNames(entry), ["data"]);
    assert.ok(ts.isFunctionDeclaration(entry.node));
  });

  test("the original two-argument form seeds the payload and trusts the context", () => {
    const [entry] = entriesOf(
      "app/server/orders.ts",
      `
        import { createServerFn } from "@tanstack/start";
        export const approveOrder = createServerFn("POST", async (payload, ctx) => {
          return db.order.update({ where: { id: payload.id } });
        });
      `
    );
    assert.deepEqual(addresses([entry]), ["POST approveOrder"]);
    assert.deepEqual(seedNames(entry), ["payload"]);
    assert.equal(entry.seeds[0].origin, "data (caller-supplied server-function input)");
    assert.deepEqual(entry.trustedParameters, ["ctx"]);
  });

  test("a server function bound to nothing still carries its seeds", () => {
    const found = entriesOf(
      "app/server/orders.ts",
      `
        ${TANSTACK_IMPORT}
        register(createServerFn().handler(async ({ data }) => db.order.create({ data })));
      `
    );
    assert.deepEqual(addresses(found), ["POST server-function"]);
    assert.deepEqual(seedNames(found[0]), ["data"]);
  });

  /* ---------------------------------------------- TanStack Start server routes */

  test("a server file route is addressed by its path, one entry point per verb", () => {
    const found = entriesOf(
      "app/routes/api/orders.ts",
      `
        import { createServerFileRoute } from "@tanstack/react-start/server";
        export const ServerRoute = createServerFileRoute("/api/orders").methods({
          GET: async ({ params }) => list(params.tenant),
          POST: async ({ request }) => save(await request.json())
        });
      `
    );
    assert.deepEqual(addresses(found), ["GET /api/orders", "POST /api/orders"]);
    assert.deepEqual(seedNames(found[0]), ["params"]);
    assert.deepEqual(seedNames(found[1]), ["request"]);
    assert.equal(found[0].kind, "http");
  });

  test("the earlier curried API route form declares the same thing", () => {
    const found = entriesOf(
      "app/routes/api/hello.ts",
      `
        import { createAPIFileRoute } from "@tanstack/start/api";
        export const APIRoute = createAPIFileRoute("/api/hello")({
          GET: async ({ request, params }) => new Response(params.id)
        });
      `
    );
    assert.deepEqual(addresses(found), ["GET /api/hello"]);
    assert.deepEqual(seedNames(found[0]), ["request", "params"]);
  });

  test("a verb with its own middleware is read through the handler it wraps", () => {
    const found = entriesOf(
      "app/routes/api/orders.ts",
      `
        import { createServerFileRoute } from "@tanstack/react-start/server";
        export const ServerRoute = createServerFileRoute("/api/orders").methods((api) => ({
          POST: api.middleware([authed]).handler(async ({ request, context }) => save(await request.json(), context.user))
        }));
      `
    );
    assert.deepEqual(addresses(found), ["POST /api/orders"]);
    assert.deepEqual(seedNames(found[0]), ["request"]);
    assert.deepEqual(found[0].trustedParameters, ["context"]);
  });

  test("a generated route with no path argument falls back to its own location", () => {
    const found = entriesOf(
      "src/routes/api/orders/$id.ts",
      `
        import { createServerFileRoute } from "@tanstack/react-start/server";
        export const ServerRoute = createServerFileRoute().methods({
          GET: async ({ params }) => list(params.id)
        });
      `
    );
    assert.deepEqual(addresses(found), ["GET /api/orders/$id"]);
  });

  test("a flat route file name is the path it spells", () => {
    const found = entriesOf(
      "src/routes/api.orders.$id.ts",
      `
        import { createServerFileRoute } from "@tanstack/react-start/server";
        export const ServerRoute = createServerFileRoute().methods({ GET: async ({ params }) => params.id });
      `
    );
    assert.deepEqual(addresses(found), ["GET /api/orders/$id"]);
  });

  /* ---------------------------------------------- what the TanStack shapes refuse to claim */

  test("createServerFn without the framework it belongs to is not claimed", () => {
    const found = entriesOf(
      "src/lib/rpc.ts",
      `
        import { createServerFn } from "./own-rpc";
        export const approveOrder = createServerFn().handler(async ({ data }) => data);
      `
    );
    assert.deepEqual(found, [], "the name alone proves nothing about where the data came from");
  });

  test("a project's own fluent builder ending in .handler is not a server function", () => {
    const found = entriesOf(
      "app/server/queue.ts",
      `
        ${TANSTACK_IMPORT}
        export const worker = defineJob({ name: "reindex" }).retries(3).handler(async ({ data }) => reindex(data));
      `
    );
    assert.deepEqual(found, []);
  });

  /* ---------------------------------------------- SolidStart: the "use server" directive */

  test("every export of a use-server module is an endpoint, seeded by argument", () => {
    const found = entriesOf(
      "src/lib/server/notes.ts",
      `
        "use server";
        import { db } from "../db";
        export async function saveNote(noteId, body) {
          return db.note.update({ where: { id: noteId }, data: { body } });
        }
        export const deleteNote = async (noteId) => db.note.delete({ where: { id: noteId } });
        function auditTrail(note) {
          return db.audit.create({ data: { note } });
        }
      `
    );
    assert.deepEqual(addresses(found), ["POST saveNote", "POST deleteNote"]);
    assert.deepEqual(seedNames(found[0]), ["noteId", "body"]);
    assert.equal(found[0].seeds[0].origin, "noteId (caller-supplied server-function argument)");
    assert.deepEqual(seedNames(found[1]), ["noteId"]);
    assert.equal(found[0].framework, "server-function", "no import names a framework, so none is claimed");
  });

  test("a directive that follows another directive still opens the module", () => {
    const found = entriesOf(
      "src/lib/server/notes.js",
      `
        "use strict";
        "use server";
        export async function saveNote(body) { return db.note.create({ data: body }); }
      `
    );
    assert.deepEqual(addresses(found), ["POST saveNote"]);
    assert.deepEqual(seedNames(found[0]), ["body"]);
  });

  test("a destructured argument is seeded binding by binding", () => {
    const [entry] = entriesOf(
      "src/lib/server/notes.ts",
      `
        "use server";
        export async function saveNote({ noteId, body }) { return db.note.update({ where: { id: noteId }, data: { body } }); }
      `
    );
    assert.deepEqual(seedNames(entry), ["noteId", "body"]);
  });

  test("a re-exported function is exported all the same", () => {
    const found = entriesOf(
      "src/lib/server/notes.ts",
      `
        "use server";
        async function saveNote(body) { return db.note.create({ data: body }); }
        export { saveNote };
      `
    );
    assert.deepEqual(addresses(found), ["POST saveNote"]);
    assert.deepEqual(seedNames(found[0]), ["body"]);
  });

  test("a CommonJS server module is recognised in a JavaScript file", () => {
    const found = entriesOf(
      "src/lib/server/notes.js",
      `
        'use server';
        const { db } = require("../db");
        exports.saveNote = async function (body) { return db.note.create({ data: body }); };
      `
    );
    assert.deepEqual(addresses(found), ["POST saveNote"]);
    assert.deepEqual(seedNames(found[0]), ["body"]);
  });

  test("a function that carries the directive in its own body is an endpoint on its own", () => {
    const found = entriesOf(
      "src/lib/data.ts",
      `
        export function useNotes() {
          return async function loadNotes(noteId) {
            "use server";
            return db.note.findMany({ where: { id: noteId } });
          };
        }
      `
    );
    assert.deepEqual(addresses(found), ["POST loadNotes"]);
    assert.deepEqual(seedNames(found[0]), ["noteId"]);
    assert.equal(found[0].seeds[0].origin, "noteId (caller-supplied server-function argument)");
  });

  test("a module that only mentions the directive in prose is not claimed", () => {
    const found = entriesOf(
      "src/lib/notes.ts",
      `
        // These helpers run wherever they are called; add "use server" to move them.
        export const DIRECTIVE = "use server";
        export function saveNote(body) { return body; }
      `
    );
    assert.deepEqual(found, [], "the directive has to be a directive, not a string somewhere in the file");
  });

  /* ---------------------------------------------- SolidStart: action() and query() */

  test("an action names itself, and the directive inside it is what makes it an endpoint", () => {
    const found = entriesOf(
      "src/lib/server/profile.ts",
      `
        import { action } from "@solidjs/router";
        export const updateProfile = action(async (patch) => {
          "use server";
          return db.user.update({ where: { id: viewer.id }, data: { ...patch } });
        }, "updateProfile");
      `
    );
    assert.deepEqual(addresses(found), ["POST updateProfile"]);
    assert.deepEqual(seedNames(found[0]), ["patch"]);
    assert.equal(found[0].framework, "solid-start");
    assert.ok(found[0].node, "the body is attached so the spread inside it can be analysed");
  });

  test("a query is the same surface under the other factory", () => {
    const found = entriesOf(
      "src/lib/server/notes.ts",
      `
        import { query } from "@solidjs/router";
        export const noteById = query(async (noteId) => {
          "use server";
          return db.note.findFirst({ where: { id: noteId } });
        }, "note");
      `
    );
    assert.deepEqual(addresses(found), ["POST note"]);
    assert.deepEqual(seedNames(found[0]), ["noteId"]);
  });

  test("an action inside a use-server module needs no directive of its own", () => {
    const found = entriesOf(
      "src/lib/server/profile.ts",
      `
        "use server";
        import { action } from "@solidjs/router";
        export const updateProfile = action(async (patch) => db.user.update({ data: { ...patch } }), "updateProfile");
      `
    );
    assert.deepEqual(addresses(found), ["POST updateProfile"]);
    assert.deepEqual(seedNames(found[0]), ["patch"]);
  });

  test("an action with no directive is named but not seeded, because it runs in the browser", () => {
    const [entry] = entriesOf(
      "src/routes/notes.tsx",
      `
        import { action } from "@solidjs/router";
        export const filterNotes = action(async (formData) => {
          setFilter(String(formData.get("q") ?? ""));
        }, "filterNotes");
      `
    );
    assert.deepEqual(addresses([entry]), ["POST filterNotes"]);
    assert.equal(entry.seeds, undefined, "a client-side action never receives a request to taint");
  });

  test("a project's own action helper is not Solid's", () => {
    const found = entriesOf(
      "src/lib/store.ts",
      `
        import { createSignal } from "solid-js";
        import { action } from "./store-actions";
        export const reset = action(async (state) => setState(state), "reset");
      `
    );
    assert.deepEqual(found, [], "the identifier has to be the one the framework exported");
  });

  /* ---------------------------------------------- SolidStart API routes */

  test("an API route takes its address from the file tree, brackets and all", () => {
    const found = entriesOf(
      "src/routes/api/orders/[id].ts",
      `
        import type { APIEvent } from "@solidjs/start/server";
        export async function GET({ params, request, locals }: APIEvent) {
          return json(await load(params.id, request.headers.get("accept"), locals.tenantId));
        }
      `
    );
    assert.deepEqual(addresses(found), ["GET /api/orders/[id]"]);
    assert.deepEqual(seedNames(found[0]), ["params", "request"]);
    assert.deepEqual(found[0].trustedParameters, ["locals"], "locals is whatever a middleware attached");
    assert.equal(found[0].framework, "solid-start");
    assert.equal(found[0].kind, "http");
  });

  test("the whole event is seeded when the handler keeps it under one name", () => {
    const found = entriesOf(
      "src/routes/api/orders/index.ts",
      `
        import type { APIEvent } from "@solidjs/start/server";
        export async function POST(event: APIEvent) {
          const body = await event.request.json();
          return json(await create(body));
        }
      `
    );
    assert.deepEqual(addresses(found), ["POST /api/orders"]);
    assert.deepEqual(seedNames(found[0]), ["event"]);
    assert.equal(found[0].seeds[0].origin, "event (inbound request)");
  });

  test("a route group shares a layout rather than adding a segment", () => {
    const found = entriesOf(
      "src/routes/(admin)/api/tenants.ts",
      `
        import type { APIEvent } from "@solidjs/start/server";
        export async function DELETE({ params }: APIEvent) { return remove(params.id); }
      `
    );
    assert.deepEqual(addresses(found), ["DELETE /api/tenants"]);
  });

  test("a route file with no Solid dependency at all is not claimed", () => {
    const file = parsed(
      "src/routes/api/orders.ts",
      `
        import { listOrders } from "../../lib/orders";
        export async function GET(event) { return listOrders(event); }
      `
    );
    assert.equal(tanstackSolidAdapter.applies(file), false);
  });

  test("a Solid component that merely renders is not an endpoint", () => {
    const file = parsed(
      "src/routes/notes.tsx",
      `
        import { createSignal } from "solid-js";
        export default function Notes() {
          const [q, setQ] = createSignal("");
          return <input value={q()} onInput={(event) => setQ(event.currentTarget.value)} />;
        }
      `
    );
    assert.deepEqual(tanstackSolidAdapter.applies(file) ? tanstackSolidAdapter.detect(file) : [], []);
  });
}
