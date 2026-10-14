import test from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import ts from "typescript";

/**
 * The Deno adapter — Deno.serve, Deno.serveHttp, std/http's serve, and Fresh —
 * driven directly rather than through `scan()`.
 *
 * Every case is written as source here. A framework adapter that only fires on a
 * fixture it has already seen is worthless in a real repository, and a test that
 * reads the corpus cannot tell the difference.
 *
 * Two things are asserted for every shape, because an entry point that gets one
 * of them wrong is worse than no entry point at all: the address a reader will
 * see in the report, and the seeds the taint model will trust. Each shape is
 * paired with a near miss that must not be claimed, because the cost of claiming
 * one is a wrong seed feeding every data-flow rule in the engine at once.
 */
const here = path.dirname(fileURLToPath(import.meta.url));
const built = path.join(here, "../dist/ast/frameworks/deno.js");

if (!existsSync(built)) {
  test.skip("the deno adapter needs a build: dist/ast/frameworks/deno.js is absent", () => {});
} else {
  const { denoAdapter, freshAdapter } = await import(pathToFileURL(built).href);

  const JAVASCRIPT = /\.[cm]?jsx?$/;

  function parsed(relativePath, text) {
    const scriptKind = JAVASCRIPT.test(relativePath)
      ? ts.ScriptKind.JS
      : relativePath.endsWith(".tsx")
        ? ts.ScriptKind.TSX
        : ts.ScriptKind.TS;
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
    if (!denoAdapter.applies(file)) return [];
    return denoAdapter.detect(file);
  }

  const addresses = (entries) => entries.map((entry) => `${entry.method} ${entry.path}`);
  const seedNames = (entry) => (entry.seeds ?? []).map((seed) => seed.name);
  const originOf = (entry, name) => (entry.seeds ?? []).find((seed) => seed.name === name)?.origin;

  /* ------------------------------------------------------------ Deno.serve */

  test("a bare handler is the whole server, so it answers every verb at every path", () => {
    const found = entriesOf("main.ts", `Deno.serve(async (request) => new Response(request.url));`);
    assert.deepEqual(addresses(found), ["ANY /"]);
    assert.deepEqual(seedNames(found[0]), ["request"]);
    assert.equal(originOf(found[0], "request"), "request (inbound request)");
    assert.equal(found[0].framework, "deno");
    assert.equal(found[0].kind, "http");
    assert.ok(found[0].node, "the handler body is attached so taint has something to analyse");
  });

  test("the options-then-handler form is the same server with a port on it", () => {
    const found = entriesOf(
      "main.ts",
      `Deno.serve({ port: 8080, hostname: "0.0.0.0" }, async (request, info) => new Response(request.url));`
    );
    assert.deepEqual(addresses(found), ["ANY /"]);
    assert.deepEqual(seedNames(found[0]), ["request"]);
  });

  test("the connection info parameter is the runtime's, not the caller's", () => {
    const found = entriesOf("main.ts", `Deno.serve({ port: 1 }, async (request, info) => new Response(info.remoteAddr));`);
    assert.deepEqual(found[0].trustedParameters, ["info"]);
  });

  test("a handler named by the parameter list alone is still seeded under its own name", () => {
    const found = entriesOf("main.ts", `Deno.serve(async (incoming) => new Response(await incoming.text()));`);
    assert.deepEqual(seedNames(found[0]), ["incoming"]);
  });

  test("the fetch member of an options object is the handler", () => {
    const found = entriesOf(
      "main.ts",
      `Deno.serve({ port: 8080, fetch(request) { return new Response(request.url); } });`
    );
    assert.deepEqual(addresses(found), ["ANY /"]);
    assert.deepEqual(seedNames(found[0]), ["request"]);
  });

  test("the handler member of an options object is the handler", () => {
    const found = entriesOf("main.ts", `Deno.serve({ handler: async (req) => new Response(req.url) });`);
    assert.deepEqual(seedNames(found[0]), ["req"]);
  });

  test("a handler member naming a function declared in the same file is resolved", () => {
    const found = entriesOf(
      "main.ts",
      `
        async function serveIt(req) { return new Response(req.url); }
        Deno.serve({ port: 3, handler: serveIt });
      `
    );
    assert.deepEqual(seedNames(found[0]), ["req"]);
    assert.ok(ts.isFunctionDeclaration(found[0].node));
  });

  test("an imported handler still declares the entry point, without inventing seeds for it", () => {
    const found = entriesOf(
      "main.ts",
      `
        import { handle } from "./handle.ts";
        Deno.serve({ port: 8080 }, handle);
      `
    );
    assert.deepEqual(addresses(found), ["ANY /"]);
    assert.equal(found[0].seeds, undefined);
    assert.equal(found[0].node, undefined);
  });

  test("a JavaScript file with the handler bound above the call is recognised", () => {
    const found = entriesOf(
      "main.js",
      `
        const handler = async (request) => new Response(request.url);
        Deno.serve({ port: 3 }, handler);
      `
    );
    assert.deepEqual(seedNames(found[0]), ["request"]);
  });

  test("a destructured parameter is not guessed at", () => {
    const found = entriesOf("main.ts", `Deno.serve(async ({ headers }) => new Response(headers.get("x")));`);
    assert.deepEqual(addresses(found), ["ANY /"]);
    assert.equal(found[0].seeds, undefined, "a guessed seed would put attacker control on the wrong binding");
  });

  /* -------------------------------------------------- the address a body settles */

  test("one pathname and one verb compared against literals give the handler an address", () => {
    const found = entriesOf(
      "main.ts",
      `
        Deno.serve((request) => {
          const { pathname } = new URL(request.url);
          if (pathname === "/health" && request.method === "GET") return new Response("ok");
          return new Response("no", { status: 404 });
        });
      `
    );
    assert.deepEqual(addresses(found), ["GET /health"]);
  });

  test("a dispatcher over several paths has no single address and admits it", () => {
    const found = entriesOf(
      "main.ts",
      `
        Deno.serve((request) => {
          const url = new URL(request.url);
          if (url.pathname === "/orders") return new Response("orders");
          if (url.pathname === "/invoices") return new Response("invoices");
          return new Response("no", { status: 404 });
        });
      `
    );
    assert.deepEqual(addresses(found), ["ANY /"], "labelling the body with one branch mislabels the others");
  });

  test("a URL pattern is not read as an address, because a handler may hold several", () => {
    const found = entriesOf(
      "main.ts",
      `
        const ORDERS = new URLPattern({ pathname: "/orders/:id" });
        Deno.serve((request) => {
          const match = ORDERS.exec(request.url);
          return new Response(match ? match.pathname.groups.id : "no");
        });
      `
    );
    assert.deepEqual(addresses(found), ["ANY /"]);
    assert.deepEqual(seedNames(found[0]), ["request"]);
  });

  /* --------------------------------------------------------- Deno.serveHttp */

  test("the request event loop is the entry point, and the loop variable is the seed", () => {
    const found = entriesOf(
      "main.ts",
      `
        async function handleConn(conn) {
          const httpConn = Deno.serveHttp(conn);
          for await (const requestEvent of httpConn) {
            requestEvent.respondWith(new Response(new URL(requestEvent.request.url).search));
          }
        }
      `
    );
    assert.deepEqual(addresses(found), ["ANY /"]);
    assert.deepEqual(seedNames(found[0]), ["requestEvent"]);
    assert.equal(originOf(found[0], "requestEvent"), "requestEvent.request (inbound request)");
    assert.ok(ts.isFunctionDeclaration(found[0].node), "the enclosing function is the scope taint can analyse");
  });

  test("the loop variable is named in its own origin rather than by a fixed wording", () => {
    const found = entriesOf(
      "main.ts",
      `
        const boot = async (conn) => {
          for await (const ev of Deno.serveHttp(conn)) {
            ev.respondWith(new Response(ev.request.url));
          }
        };
      `
    );
    assert.deepEqual(seedNames(found[0]), ["ev"]);
    assert.equal(originOf(found[0], "ev"), "ev.request (inbound request)");
  });

  test("a destructured loop variable is read for its request element only", () => {
    const found = entriesOf(
      "main.ts",
      `
        async function handleConn(conn) {
          for await (const { request, respondWith } of Deno.serveHttp(conn)) {
            respondWith(new Response(request.url));
          }
        }
      `
    );
    assert.deepEqual(seedNames(found[0]), ["request"], "respondWith writes the response and is not the caller's");
    assert.equal(originOf(found[0], "request"), "request (inbound request)");
  });

  test("a serveHttp call with no loop to consume it gets the address and no seeds", () => {
    const found = entriesOf("main.ts", `function boot(conn) { return Deno.serveHttp(conn); }`);
    assert.deepEqual(addresses(found), ["ANY /"]);
    assert.equal(found[0].seeds, undefined);
  });

  test("a plain for-of over the connection is not an awaited request loop", () => {
    const found = entriesOf(
      "main.ts",
      `
        function boot(conn) {
          const c = Deno.serveHttp(conn);
          for (const event of c) { record(event); }
        }
      `
    );
    assert.equal(found[0].seeds, undefined);
  });

  /* ------------------------------------------------- the standard library's serve */

  test("the standard library's serve takes its handler first and is claimed on its import", () => {
    const found = entriesOf(
      "main.ts",
      `
        import { serve } from "https://deno.land/std@0.190.0/http/server.ts";
        serve(async (request, connInfo) => new Response(request.url), { port: 8000 });
      `
    );
    assert.deepEqual(addresses(found), ["ANY /"]);
    assert.deepEqual(seedNames(found[0]), ["request"]);
    assert.deepEqual(found[0].trustedParameters, ["connInfo"]);
  });

  test("the jsr specifier for the same module is the same framework", () => {
    const found = entriesOf(
      "main.ts",
      `
        import { serveTls } from "jsr:@std/http/server";
        serveTls((request) => new Response(request.url), { port: 443 });
      `
    );
    assert.deepEqual(seedNames(found[0]), ["request"]);
  });

  test("a serve imported from somewhere else is somebody else's function", () => {
    const file = parsed(
      "main.ts",
      `
        import { serve } from "micro";
        serve(async (req) => new Response(req.url));
      `
    );
    assert.equal(denoAdapter.applies(file), false);
  });

  /* ------------------------------------------------------------------- Fresh */

  test("a Handlers object publishes one entry point per verb, addressed by the file name", () => {
    const found = entriesOf(
      "routes/api/orders/[id].ts",
      `
        import { Handlers } from "$fresh/server.ts";
        export const handler: Handlers = {
          async GET(req, ctx) { return new Response(ctx.params.id); },
          async DELETE(req, ctx) { return new Response(ctx.params.id); }
        };
      `
    );
    assert.deepEqual(addresses(found), ["GET /api/orders/[id]", "DELETE /api/orders/[id]"]);
    assert.deepEqual(seedNames(found[0]), ["req", "ctx"]);
    assert.equal(originOf(found[0], "req"), "request (inbound request)");
    assert.equal(originOf(found[0], "ctx"), "ctx.params (route parameters)");
  });

  test("index addresses the directory it sits in rather than a segment of its own", () => {
    const found = entriesOf(
      "routes/index.tsx",
      `
        import type { Handlers } from "$fresh/server.ts";
        export const handler: Handlers = { GET(req, ctx) { return ctx.render(); } };
      `
    );
    assert.deepEqual(addresses(found), ["GET /"]);
  });

  test("a route group organises the tree without appearing in the URL", () => {
    const found = entriesOf(
      "routes/(marketing)/blog/[...slug].tsx",
      `
        import type { Handlers } from "$fresh/server.ts";
        export const handler: Handlers = { GET(req, ctx) { return new Response(ctx.params.slug); } };
      `
    );
    assert.deepEqual(addresses(found), ["GET /blog/[...slug]"]);
  });

  test("middleware is reported at the root because every request below it passes through", () => {
    const found = entriesOf(
      "routes/_middleware.ts",
      `
        import type { FreshContext } from "$fresh/server.ts";
        export async function handler(req: Request, ctx: FreshContext) { return await ctx.next(); }
      `
    );
    assert.deepEqual(addresses(found), ["ANY /"]);
    assert.deepEqual(seedNames(found[0]), ["req", "ctx"]);
  });

  test("the app shell and the error pages are not endpoints a caller can address", () => {
    for (const name of ["_app.tsx", "_layout.tsx", "_404.tsx", "_500.tsx"]) {
      const file = parsed(
        `routes/${name}`,
        `
          import type { Handlers } from "$fresh/server.ts";
          export const handler: Handlers = { GET(req, ctx) { return ctx.render(); } };
        `
      );
      assert.equal(denoAdapter.applies(file), false, `${name} must not be claimed`);
    }
  });

  test("a single exported function answers every verb the file is routed for", () => {
    const found = entriesOf(
      "routes/api/joke.ts",
      `
        import type { Handler } from "$fresh/server.ts";
        export const handler: Handler = (req, ctx) => new Response(ctx.params.id);
      `
    );
    assert.deepEqual(addresses(found), ["ANY /api/joke"]);
    assert.deepEqual(seedNames(found[0]), ["req", "ctx"]);
  });

  test("a verb whose value names a function declared in the same file is resolved", () => {
    const found = entriesOf(
      "routes/api/orders.ts",
      `
        import type { Handlers } from "$fresh/server.ts";
        async function listOrders(req, ctx) { return new Response(ctx.params.id); }
        export const handler: Handlers = { GET: listOrders };
      `
    );
    assert.deepEqual(addresses(found), ["GET /api/orders"]);
    assert.ok(ts.isFunctionDeclaration(found[0].node));
    assert.deepEqual(seedNames(found[0]), ["req", "ctx"]);
  });

  test("the typed factory form collapses the pair into one context, and says so", () => {
    const found = entriesOf(
      "routes/api/kv.ts",
      `
        import { define } from "../../utils.ts";
        export const handler = define.handlers({ async GET(ctx) { return new Response(ctx.url); } });
      `
    );
    assert.deepEqual(addresses(found), ["GET /api/kv"]);
    assert.deepEqual(seedNames(found[0]), ["ctx"]);
    assert.equal(originOf(found[0], "ctx"), "ctx (inbound request and route parameters)");
  });

  test("a JavaScript route file without type annotations is claimed on its import", () => {
    const found = entriesOf(
      "routes/api/ping.js",
      `
        import { Handlers } from "$fresh/server.ts";
        export const handler = { GET(req, ctx) { return new Response(ctx.params.id); } };
      `
    );
    assert.deepEqual(addresses(found), ["GET /api/ping"]);
    assert.deepEqual(seedNames(found[0]), ["req", "ctx"]);
  });

  test("the app's own routes tree wins inside a monorepo path", () => {
    const found = entriesOf(
      "apps/site/routes/api/[org]/members.ts",
      `
        import type { Handlers } from "$fresh/server.ts";
        export const handler: Handlers = { DELETE(req, ctx) { return new Response(ctx.params.org); } };
      `
    );
    assert.deepEqual(addresses(found), ["DELETE /api/[org]/members"]);
  });

  /* -------------------------------------------- what the Fresh half refuses to claim */

  test("a routes directory that has nothing to do with Fresh is not claimed", () => {
    const file = parsed(
      "routes/search.js",
      `
        import { entities } from "../lib/markup.js";
        export const method = "GET";
        export const path = "/search";
        export async function handler({ query, html }) { return html(entities(query.get("q"))); }
      `
    );
    assert.equal(denoAdapter.applies(file), false, "seeding this file's parameters would describe the wrong bindings");
  });

  test("an Express handler under routes is not a Fresh handler because it is called handler", () => {
    const file = parsed(
      "routes/search.ts",
      `
        import type { Handler } from "express";
        export const handler: Handler = (req, res, next) => { res.send(req.query.q); };
      `
    );
    assert.equal(denoAdapter.applies(file), false, "seeding the second parameter would make the response caller data");
  });

  test("a three-parameter verb method gets the route and no seeds", () => {
    const found = entriesOf(
      "routes/x.ts",
      `
        import type { Handlers } from "$fresh/server.ts";
        export const handler = { GET(req, res, next) { next(); } } as unknown as Handlers;
      `
    );
    assert.deepEqual(addresses(found), ["GET /x"]);
    assert.equal(found[0].seeds, undefined);
  });

  test("lower-case keys are not verbs, and Fresh does not route them", () => {
    const found = entriesOf(
      "routes/x.ts",
      `
        import type { Handlers } from "$fresh/server.ts";
        export const handler: Handlers = { get(req, ctx) { return ctx.render(); }, helper(a) { return a; } };
      `
    );
    assert.deepEqual(found, []);
  });

  test("a Fresh handler outside a routes tree has no address and is not claimed", () => {
    const file = parsed(
      "src/handlers/orders.ts",
      `
        import type { Handlers } from "$fresh/server.ts";
        export const handler: Handlers = { GET(req, ctx) { return new Response(ctx.params.id); } };
      `
    );
    assert.equal(denoAdapter.applies(file), false);
  });

  test("a route file that exports only a page component is not an entry point", () => {
    const file = parsed(
      "routes/about.tsx",
      `
        import type { PageProps } from "$fresh/server.ts";
        export default function About(props: PageProps) { return null; }
      `
    );
    assert.equal(denoAdapter.applies(file), false);
  });

  /* ------------------------------------------ what the Deno half refuses to claim */

  test("a lower-case deno is somebody's own variable", () => {
    const file = parsed("main.ts", `deno.serve(async (req) => new Response(req.url));`);
    assert.equal(denoAdapter.applies(file), false);
  });

  test("a mention in prose is not a server", () => {
    const file = parsed("src/notes.ts", `// one day we should move this to Deno.serve\nexport const notes = 1;`);
    assert.equal(denoAdapter.applies(file), false);
  });

  test("a call with no arguments has no handler to describe", () => {
    assert.deepEqual(entriesOf("main.ts", `Deno.serve();`), []);
  });

  /* ------------------------------------------------------ shapes left to serverless */

  test("a default-exported fetch object is left to the adapter that already claims it", () => {
    const found = entriesOf(
      "main.ts",
      `
        import { db } from "jsr:@acme/db";
        export default { async fetch(request: Request) { return new Response(request.url); } };
      `
    );
    assert.deepEqual(found, [], "two adapters claiming one handler would report it twice");
  });

  test("a fetch event listener is left to the adapter that already claims it", () => {
    const found = entriesOf(
      "main.ts",
      `addEventListener("fetch", (event) => { event.respondWith(new Response(event.request.url)); });`
    );
    assert.deepEqual(found, []);
  });

  /* ------------------------------------------------------------------ registry */

  test("Fresh rides along with the same pass, so one handler cannot be claimed twice", () => {
    assert.equal(freshAdapter, denoAdapter);
    assert.equal(denoAdapter.id, "deno");
  });

  test("a file holding both a Fresh route and a development server declares each once", () => {
    const found = entriesOf(
      "routes/dev.ts",
      `
        import type { Handlers } from "$fresh/server.ts";
        export const handler: Handlers = { GET(req, ctx) { return new Response(ctx.params.id); } };
        if (import.meta.main) Deno.serve((request) => new Response(request.url));
      `
    );
    assert.deepEqual(addresses(found), ["GET /dev", "ANY /"]);
    assert.deepEqual(seedNames(found[0]), ["req", "ctx"]);
    assert.deepEqual(seedNames(found[1]), ["request"]);
  });
}
