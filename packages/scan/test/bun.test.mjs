import test from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import ts from "typescript";

/**
 * The Bun adapter, driven directly rather than through `scan()`.
 *
 * Every case is written as source here. A framework adapter that only fires on a
 * fixture it has already seen is worthless in a real repository, and a test that
 * reads the corpus cannot tell the difference.
 *
 * Two things are asserted for every shape, because an entry point that gets one
 * of them wrong is worse than no entry point at all: the address a reader will
 * see in the report, and the bindings the taint model will trust. Every shape is
 * paired with a near miss, because the expensive failure of this adapter is not a
 * route it fails to find — it is a seed on a function no caller ever reaches.
 */
const here = path.dirname(fileURLToPath(import.meta.url));
const built = path.join(here, "../dist/ast/frameworks/bun.js");

if (!existsSync(built)) {
  test.skip("the bun adapter needs a build: dist/ast/frameworks/bun.js is absent", () => {});
} else {
  const { bunAdapter } = await import(pathToFileURL(built).href);

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
    if (!bunAdapter.applies(file)) return [];
    return bunAdapter.detect(file);
  }

  const addresses = (entries) => entries.map((entry) => `${entry.method} ${entry.path}`);
  const seedNames = (entry) => (entry.seeds ?? []).map((seed) => seed.name);

  /* -------------------------------------------------- the fetch handler */

  test("the fetch handler is the catch-all, so it is reported as ANY /", () => {
    const found = entriesOf(
      "src/server.ts",
      `
        Bun.serve({
          port: 3000,
          fetch(request, server) {
            return new Response(request.url);
          }
        });
      `
    );
    assert.deepEqual(addresses(found), ["ANY /"]);
    assert.equal(found[0].framework, "bun");
    assert.equal(found[0].kind, "http");
    assert.ok(found[0].node, "the handler body is attached so taint has something to analyse");
  });

  test("the request parameter is seeded and the server parameter is not", () => {
    const [entry] = entriesOf(
      "src/server.ts",
      `Bun.serve({ fetch(request, server) { return server.upgrade(request); } });`
    );
    assert.deepEqual(seedNames(entry), ["request"]);
    assert.equal(entry.seeds[0].origin, "request (inbound request)");
    assert.deepEqual(entry.trustedParameters, ["server"]);
  });

  test("a differently named request parameter is seeded under that name", () => {
    const [entry] = entriesOf("src/server.ts", `Bun.serve({ fetch: async (req) => new Response(req.url) });`);
    assert.deepEqual(seedNames(entry), ["req"]);
  });

  test("a shorthand fetch resolves to the function declared beside it", () => {
    const [entry] = entriesOf(
      "src/server.ts",
      `
        const port = 3000;
        async function fetch(request) {
          return new Response(request.url);
        }
        Bun.serve({ port, fetch });
      `
    );
    assert.deepEqual(addresses([entry]), ["ANY /"]);
    assert.deepEqual(seedNames(entry), ["request"]);
    assert.ok(ts.isFunctionDeclaration(entry.node));
  });

  test("a fetch named as a const is resolved through that name", () => {
    const [entry] = entriesOf(
      "src/server.ts",
      `
        const handleRequest = async (incoming) => new Response(incoming.url);
        Bun.serve({ fetch: handleRequest });
      `
    );
    assert.deepEqual(seedNames(entry), ["incoming"]);
  });

  test("an imported fetch keeps the address and invents no seed", () => {
    const [entry] = entriesOf(
      "src/server.ts",
      `
        import { handleRequest } from "./handler";
        Bun.serve({ port: 3000, fetch: handleRequest });
      `
    );
    assert.deepEqual(addresses([entry]), ["ANY /"]);
    assert.equal(entry.seeds, undefined);
    assert.equal(entry.node, undefined);
  });

  test("a destructured request parameter is not guessed at", () => {
    const [entry] = entriesOf("src/server.ts", `Bun.serve({ fetch({ url, headers }) { return new Response(url); } });`);
    assert.deepEqual(addresses([entry]), ["ANY /"]);
    assert.equal(entry.seeds, undefined);
  });

  test("a type argument on serve does not hide the configuration", () => {
    const found = entriesOf(
      "src/server.ts",
      `
        type Data = { userId: string };
        Bun.serve<Data>({ fetch(request) { return new Response(request.url); } });
      `
    );
    assert.deepEqual(addresses(found), ["ANY /"]);
    assert.deepEqual(seedNames(found[0]), ["request"]);
  });

  test("a configuration hoisted into a const is the same server", () => {
    const found = entriesOf(
      "src/server.ts",
      `
        const config = { port: 3000, fetch(request) { return new Response(request.url); } };
        Bun.serve(config);
      `
    );
    assert.deepEqual(addresses(found), ["ANY /"]);
    assert.deepEqual(seedNames(found[0]), ["request"]);
  });

  /* -------------------------------------------------- routes, which state their own address */

  test("a method-keyed route reports one address per verb, with the parameter as written", () => {
    const found = entriesOf(
      "src/server.ts",
      `
        Bun.serve({
          routes: {
            "/api/users/:id": {
              GET: (request) => new Response(request.params.id),
              POST: (request) => new Response(request.params.id)
            }
          }
        });
      `
    );
    assert.deepEqual(addresses(found), ["GET /api/users/:id", "POST /api/users/:id"]);
    assert.deepEqual(seedNames(found[0]), ["request"]);
    assert.deepEqual(seedNames(found[1]), ["request"]);
  });

  test("a bare handler under a route answers any verb", () => {
    const found = entriesOf(
      "src/server.ts",
      `Bun.serve({ routes: { "/webhooks/stripe": async (req) => new Response(await req.text()) } });`
    );
    assert.deepEqual(addresses(found), ["ANY /webhooks/stripe"]);
    assert.deepEqual(seedNames(found[0]), ["req"]);
  });

  test("a wildcard route keeps Bun's own syntax", () => {
    const found = entriesOf(
      "src/server.ts",
      `Bun.serve({ routes: { "/assets/*": (request, server) => new Response(request.url) } });`
    );
    assert.deepEqual(addresses(found), ["ANY /assets/*"]);
    assert.deepEqual(found[0].trustedParameters, ["server"]);
  });

  test("routes and a fallback fetch are both reported", () => {
    const found = entriesOf(
      "src/server.ts",
      `
        Bun.serve({
          routes: { "/health": { GET: () => new Response("ok") } },
          fetch(request) { return new Response(request.url); }
        });
      `
    );
    assert.deepEqual(addresses(found).sort(), ["ANY /", "GET /health"]);
  });

  test("a route handler named elsewhere in the file is resolved", () => {
    const found = entriesOf(
      "src/server.ts",
      `
        async function listOrders(request) { return new Response(request.url); }
        Bun.serve({ routes: { "/orders": { GET: listOrders } } });
      `
    );
    assert.deepEqual(addresses(found), ["GET /orders"]);
    assert.deepEqual(seedNames(found[0]), ["request"]);
  });

  test("an imported route handler keeps the address it declares and no seeds", () => {
    const found = entriesOf(
      "src/server.ts",
      `
        import { renderInvoice } from "./invoices";
        Bun.serve({ routes: { "/invoices/:id": { GET: renderInvoice } } });
      `
    );
    assert.deepEqual(addresses(found), ["GET /invoices/:id"]);
    assert.equal(found[0].seeds, undefined);
  });

  test("a canned Response is not a handler, so no entry point is claimed for it", () => {
    const found = entriesOf(
      "src/server.ts",
      `
        Bun.serve({
          routes: {
            "/robots.txt": new Response("User-agent: *"),
            "/version": Response.json({ version: 1 })
          }
        });
      `
    );
    assert.deepEqual(found, []);
  });

  test("a routes key that is not a path is not a route", () => {
    const found = entriesOf(
      "src/server.ts",
      `Bun.serve({ routes: { fallback: (request) => new Response(request.url) } });`
    );
    assert.deepEqual(found, []);
  });

  /* -------------------------------------------------- websockets */

  test("the websocket message callback is the client's payload, and the socket is not", () => {
    const found = entriesOf(
      "src/server.ts",
      `
        Bun.serve({
          fetch(request, server) { return server.upgrade(request) ? undefined : new Response("no"); },
          websocket: {
            open(ws) { ws.subscribe("all"); },
            message(ws, message) { ws.publish("all", message); },
            close(ws, code, reason) { ws.unsubscribe("all"); }
          }
        });
      `
    );
    const socket = found.find((entry) => entry.kind === "ipc");
    assert.ok(socket, "the message callback is an entry point");
    assert.equal(socket.method, "MESSAGE");
    assert.equal(socket.path, "websocket");
    assert.deepEqual(seedNames(socket), ["message"]);
    assert.equal(socket.seeds[0].origin, "message (payload sent by the connected client)");
    assert.deepEqual(socket.trustedParameters, ["ws"]);
    // open and close receive the socket and the runtime's own close codes; only
    // one of these three callbacks is reachable with data a client composed.
    assert.equal(found.filter((entry) => entry.kind === "ipc").length, 1);
  });

  test("a websocket handler object declared beside the server is resolved", () => {
    const found = entriesOf(
      "src/server.ts",
      `
        const websocket = { message(socket, frame) { socket.send(frame); } };
        Bun.serve({ websocket, fetch(request, server) { return server.upgrade(request); } });
      `
    );
    const socket = found.find((entry) => entry.kind === "ipc");
    assert.deepEqual(seedNames(socket), ["frame"]);
    assert.deepEqual(socket.trustedParameters, ["socket"]);
  });

  test("a websocket block with no message callback claims nothing", () => {
    const found = entriesOf(
      "src/server.ts",
      `Bun.serve({ websocket: { open(ws) { ws.subscribe("all"); } }, fetch(request) { return new Response(request.url); } });`
    );
    assert.deepEqual(addresses(found), ["ANY /"]);
  });

  /* -------------------------------------------------- the other ways a server is started */

  test("serve imported from bun is the same server", () => {
    const found = entriesOf(
      "src/server.ts",
      `
        import { serve } from "bun";
        serve({ port: 3000, fetch(request) { return new Response(request.url); } });
      `
    );
    assert.deepEqual(addresses(found), ["ANY /"]);
    assert.deepEqual(seedNames(found[0]), ["request"]);
  });

  test("serve imported under another name is followed", () => {
    const found = entriesOf(
      "src/server.ts",
      `
        import { serve as startServer } from "bun";
        startServer({ fetch(request) { return new Response(request.url); } });
      `
    );
    assert.deepEqual(seedNames(found[0]), ["request"]);
  });

  test("a CommonJS require of bun is recognised in a JavaScript file", () => {
    const found = entriesOf(
      "src/server.js",
      `
        const { serve } = require("bun");
        serve({ fetch(request) { return new Response(request.url); } });
      `
    );
    assert.deepEqual(addresses(found), ["ANY /"]);
    assert.deepEqual(seedNames(found[0]), ["request"]);
  });

  test("reloading a running server swaps in a configuration that is just as reachable", () => {
    const found = entriesOf(
      "src/server.ts",
      `
        const server = Bun.serve({ fetch: (request) => new Response(request.url) });
        server.reload({ fetch(next) { return new Response(next.url); } });
      `
    );
    assert.deepEqual(addresses(found), ["ANY /", "ANY /"]);
    assert.deepEqual(seedNames(found[1]), ["next"]);
  });

  /* -------------------------------------------------- the default-export server */

  test("a default-exported server object is claimed when the file works with Bun", () => {
    const found = entriesOf(
      "src/server.ts",
      `
        import { Database } from "bun:sqlite";
        const db = new Database("app.db");
        export default {
          port: 3000,
          fetch(request) { return new Response(request.url + db.filename); }
        };
      `
    );
    assert.deepEqual(addresses(found), ["ANY /"]);
    assert.deepEqual(seedNames(found[0]), ["request"]);
  });

  test("a Bun dependency loaded lazily still identifies the runtime", () => {
    const found = entriesOf(
      "src/server.ts",
      `
        export default {
          port: 3000,
          async fetch(request) {
            const { Database } = await import("bun:sqlite");
            return new Response(request.url + new Database("app.db").filename);
          }
        };
      `
    );
    assert.deepEqual(seedNames(found[0]), ["request"]);
  });

  test("a bare default export is claimed on the strength of its request parameter", () => {
    const found = entriesOf(
      "src/server.ts",
      `
        const port = Bun.env.PORT;
        export default { fetch(request) { return new Response(request.url + port); } };
      `
    );
    assert.deepEqual(seedNames(found[0]), ["request"]);
  });

  test("a default export whose handler is annotated as a Request is a server", () => {
    const found = entriesOf(
      "src/server.ts",
      `
        const root = Bun.env.ROOT;
        export default { fetch(incoming: Request) { return new Response(root + incoming.url); } };
      `
    );
    assert.deepEqual(seedNames(found[0]), ["incoming"]);
  });

  test("a CommonJS default-exported server is the same shape written the other way", () => {
    const found = entriesOf(
      "src/server.js",
      `
        const root = Bun.env.ROOT;
        module.exports = { port: 3000, fetch(request) { return new Response(root + request.url); } };
      `
    );
    assert.deepEqual(addresses(found), ["ANY /"]);
    assert.deepEqual(seedNames(found[0]), ["request"]);
  });

  test("a module exporting a fetch wrapper is not a server", () => {
    const found = entriesOf(
      "src/http.ts",
      `
        const cache = Bun.file("./cache.json");
        export default {
          fetch(url, options) { return globalThis.fetch(url, options); }
        };
      `
    );
    assert.deepEqual(found, []);
  });

  test("a default-exported fetch handler with no Bun dependency belongs to another runtime", () => {
    const file = parsed(
      "src/worker.ts",
      `export default { async fetch(request, env, ctx) { return new Response(request.url); } };`
    );
    assert.equal(bunAdapter.applies(file), false);
  });

  /* -------------------------------------------------- what the adapter refuses to claim */

  test("the error callback receives the exception, not the caller", () => {
    const found = entriesOf(
      "src/server.ts",
      `
        Bun.serve({
          fetch(request) { return new Response(request.url); },
          error(error) { return new Response(error.message, { status: 500 }); }
        });
      `
    );
    assert.deepEqual(addresses(found), ["ANY /"]);
    assert.equal(found.length, 1, "a seeded error object would invent a flow no request can reach");
  });

  test("a file that only reads a file through Bun is not a server", () => {
    const file = parsed("src/config.ts", `export const config = await Bun.file("config.json").json();`);
    assert.equal(bunAdapter.applies(file), false);
  });

  test("a serve from another library is not Bun's, even beside a Bun helper", () => {
    const found = entriesOf(
      "src/server.ts",
      `
        import { serve } from "@hono/node-server";
        const secret = Bun.env.SECRET;
        serve({ port: 3000, fetch(request) { return new Response(request.url + secret); } });
      `
    );
    assert.deepEqual(found, []);
  });

  test("reload on an object that is not a Bun server is somebody else's method", () => {
    const found = entriesOf(
      "src/config.ts",
      `
        const port = Bun.env.PORT;
        watcher.reload({ fetch(request) { return request; } });
      `
    );
    assert.deepEqual(found, []);
  });

  test("a routes object outside a serve call is not a Bun route table", () => {
    const found = entriesOf(
      "src/registry.ts",
      `
        const cache = Bun.file("routes.json");
        export const registry = { routes: { "/orders": (request) => request.url } };
      `
    );
    assert.deepEqual(found, []);
  });

  test("a mention of Bun.serve() in prose claims nothing", () => {
    const found = entriesOf("src/notes.ts", `// we should move this onto Bun.serve() one day\nexport const notes = 1;`);
    assert.deepEqual(found, []);
  });

  test("a file with no Bun surface at all is never walked", () => {
    const file = parsed("src/app.ts", `import express from "express";\nexpress().get("/", (req, res) => res.end());`);
    assert.equal(bunAdapter.applies(file), false);
  });
}

