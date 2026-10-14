import test from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import ts from "typescript";

/**
 * The Socket.IO / WebSocket / BroadcastChannel adapter, driven directly rather
 * than through `scan()`.
 *
 * Every case is written as source here. A framework adapter that only fires on a
 * fixture it has already seen is worthless in a real repository, and a test that
 * reads the corpus cannot tell the difference.
 *
 * Two things are asserted for every shape, because an entry point that gets one
 * of them wrong is worse than no entry point at all: the address a reader will
 * see in the report, and the seeds the taint model will trust. Every shape is
 * paired with a near miss — code that looks like it and is not — because the
 * expensive mistake in this file is not a missed socket but an invented one.
 */
const here = path.dirname(fileURLToPath(import.meta.url));
const built = path.join(here, "../dist/ast/frameworks/realtime.js");

if (!existsSync(built)) {
  test.skip("the realtime adapter needs a build: dist/ast/frameworks/realtime.js is absent", () => {});
} else {
  const { realtimeAdapter } = await import(pathToFileURL(built).href);

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
    if (!realtimeAdapter.applies(file)) return [];
    return realtimeAdapter.detect(file);
  }

  const addresses = (entries) => entries.map((entry) => `${entry.method} ${entry.path}`);
  const seedNames = (entry) => (entry.seeds ?? []).map((seed) => seed.name);
  const at = (entries, address) => entries.find((entry) => `${entry.method} ${entry.path}` === address);

  /* ============================================================ Socket.IO */

  test("a gateway written inline exposes both the connection and the message", () => {
    const found = entriesOf(
      "src/gateway.ts",
      `
        import { Server } from "socket.io";
        const io = new Server(httpServer);
        io.on("connection", (socket) => {
          socket.on("chat:message", async (payload) => {
            await messages.insertOne({ room: payload.room, body: payload.body });
          });
        });
      `
    );
    assert.deepEqual(addresses(found), ["CONNECT connection", "MESSAGE chat:message"]);

    const connection = at(found, "CONNECT connection");
    assert.equal(connection.seeds, undefined, "the socket is the server's object, not the client's message");
    assert.deepEqual(connection.trustedParameters, ["socket"]);

    const message = at(found, "MESSAGE chat:message");
    assert.deepEqual(seedNames(message), ["payload"]);
    assert.equal(message.seeds[0].origin, "payload (payload sent by the connected client)");
    assert.equal(message.kind, "ipc");
    assert.equal(message.framework, "realtime");
    assert.ok(message.node, "the handler body is attached so taint has something to analyse");
  });

  test("a namespace registers its own connection handler", () => {
    const found = entriesOf(
      "src/gateway.ts",
      `
        import { Server } from "socket.io";
        const io = new Server(httpServer);
        io.of("/agents").on("connection", (socket) => {
          socket.on("ticket:claim", (ticketId) => claim(ticketId));
        });
      `
    );
    assert.deepEqual(addresses(found), ["CONNECT connection", "MESSAGE ticket:claim"]);
    assert.deepEqual(seedNames(at(found, "MESSAGE ticket:claim")), ["ticketId"]);
  });

  test("a namespace held in a variable is the same namespace", () => {
    const found = entriesOf(
      "src/gateway.ts",
      `
        import { Server } from "socket.io";
        const io = new Server(httpServer);
        const agents = io.of("/agents");
        agents.on("connection", (socket) => {
          socket.on("ticket:claim", (ticketId) => claim(ticketId));
        });
      `
    );
    assert.deepEqual(addresses(found), ["CONNECT connection", "MESSAGE ticket:claim"]);
  });

  test("the default namespace under its older name is still the server", () => {
    const found = entriesOf(
      "src/gateway.js",
      `
        const { Server } = require("socket.io");
        const io = new Server(httpServer);
        io.sockets.on("connection", (socket) => {
          socket.on("ping:room", (room) => io.to(room).emit("pong"));
        });
      `
    );
    assert.deepEqual(addresses(found), ["CONNECT connection", "MESSAGE ping:room"]);
    assert.deepEqual(seedNames(at(found, "MESSAGE ping:room")), ["room"]);
  });

  test("the server constructed straight out of require is recognised", () => {
    const found = entriesOf(
      "src/gateway.js",
      `
        const io = require("socket.io")(httpServer);
        io.on("connection", (socket) => {
          socket.on("upload:start", (meta) => begin(meta.name));
        });
      `
    );
    assert.deepEqual(addresses(found), ["CONNECT connection", "MESSAGE upload:start"]);
    assert.deepEqual(seedNames(at(found, "MESSAGE upload:start")), ["meta"]);
  });

  test("a handler module that only receives the socket is recognised by its type", () => {
    const found = entriesOf(
      "src/gateway/contacts.ts",
      `
        import type { Socket } from "socket.io";
        export function registerContactHandlers(connection: Socket): void {
          connection.on("contact:search", async (message, ack) => {
            ack(await contacts.find(message.filter).toArray());
          });
        }
      `
    );
    assert.deepEqual(addresses(found), ["MESSAGE contact:search"]);
    assert.deepEqual(seedNames(found[0]), ["message"], "the acknowledgement is the handler's reply, not the client's data");
  });

  test("an aliased type import still names the socket", () => {
    const found = entriesOf(
      "src/gateway/contacts.ts",
      `
        import type { Socket as ClientSocket } from "socket.io";
        export function register(connection: ClientSocket) {
          connection.on("contact:search", (message) => search(message.filter));
        }
      `
    );
    assert.deepEqual(addresses(found), ["MESSAGE contact:search"]);
    assert.deepEqual(seedNames(found[0]), ["message"]);
  });

  test("a helper that imports nothing is recognised by a member no other API has", () => {
    const found = entriesOf(
      "src/gateway/rooms.js",
      `
        module.exports = function register(socket) {
          const tenant = socket.handshake.auth.tenant;
          socket.on("room:join", (room) => socket.join(tenant + ":" + room));
        };
      `
    );
    assert.deepEqual(addresses(found), ["MESSAGE room:join"]);
    assert.deepEqual(seedNames(found[0]), ["room"]);
  });

  /* -------------------------------------------------- what a payload consists of */

  test("every payload parameter is seeded, and only the trailing acknowledgement is not", () => {
    for (const trailing of ["ack", "callback", "cb", "respond"]) {
      const found = entriesOf(
        "src/gateway.ts",
        `
          import type { Socket } from "socket.io";
          export function register(socket: Socket) {
            socket.on("order:place", (order, options, ${trailing}) => ${trailing}(place(order, options)));
          }
        `
      );
      assert.deepEqual(seedNames(found[0]), ["order", "options"], `${trailing} must not be seeded`);
    }
  });

  test("a trailing parameter declared as a function is the acknowledgement whatever it is called", () => {
    const found = entriesOf(
      "src/gateway.ts",
      `
        import type { Socket } from "socket.io";
        export function register(socket: Socket) {
          socket.on("order:place", (order, done: (result: unknown) => void) => done(place(order)));
        }
      `
    );
    assert.deepEqual(seedNames(found[0]), ["order"]);
  });

  test("a parameter that is not trailing is payload however it is named", () => {
    const found = entriesOf(
      "src/gateway.ts",
      `
        import type { Socket } from "socket.io";
        export function register(socket: Socket) {
          socket.on("order:place", (cb, order) => run(cb, order));
        }
      `
    );
    assert.deepEqual(seedNames(found[0]), ["cb", "order"], "only the last position carries the acknowledgement");
  });

  test("a destructured payload seeds each binding it introduces", () => {
    const found = entriesOf(
      "src/gateway.ts",
      `
        import type { Socket } from "socket.io";
        export function register(socket: Socket) {
          socket.on("conversation:search", async ({ filter, limit }) => search(filter, limit));
        }
      `
    );
    assert.deepEqual(seedNames(found[0]), ["filter", "limit"]);
    assert.equal(found[0].seeds[0].origin, "filter (payload sent by the connected client)");
  });

  test("the catch-all listener seeds the event name as well as the arguments", () => {
    const found = entriesOf(
      "src/gateway.ts",
      `
        import type { Socket } from "socket.io";
        export function register(socket: Socket) {
          socket.onAny((event, ...args) => audit(event, args));
        }
      `
    );
    assert.deepEqual(addresses(found), ["MESSAGE *"]);
    assert.deepEqual(seedNames(found[0]), ["event", "args"]);
    assert.equal(found[0].seeds[0].origin, "event (event name chosen by the connected client)");
    assert.equal(found[0].seeds[1].origin, "args (payload sent by the connected client)");
  });

  test("a computed event name is still an event, reported as one the address could not be read for", () => {
    const found = entriesOf(
      "src/gateway.ts",
      `
        import type { Socket } from "socket.io";
        const EVENT = resolveEventName();
        export function register(socket: Socket) {
          socket.on(EVENT, (payload) => handle(payload));
        }
      `
    );
    assert.deepEqual(addresses(found), ["MESSAGE *"]);
    assert.deepEqual(seedNames(found[0]), ["payload"]);
  });

  test("a named handler declared in the same file is resolved", () => {
    const found = entriesOf(
      "src/gateway.ts",
      `
        import type { Socket } from "socket.io";
        async function searchContacts(message, ack) {
          ack(await contacts.find(message.filter).toArray());
        }
        export function register(socket: Socket) {
          socket.on("contact:search", searchContacts);
        }
      `
    );
    assert.deepEqual(seedNames(found[0]), ["message"]);
    assert.ok(ts.isFunctionDeclaration(found[0].node));
  });

  test("once and the prepend variants register the same reachable event", () => {
    for (const method of ["once", "addListener", "prependListener", "prependOnceListener"]) {
      const found = entriesOf(
        "src/gateway.ts",
        `
          import type { Socket } from "socket.io";
          export function register(socket: Socket) {
            socket.${method}("import:begin", (payload) => begin(payload));
          }
        `
      );
      assert.deepEqual(addresses(found), ["MESSAGE import:begin"], `${method} is a registration`);
      assert.deepEqual(seedNames(found[0]), ["payload"]);
    }
  });

  /* -------------------------------------------------- what Socket.IO does not claim */

  test("a lifecycle event carries the library's own arguments and is not an entry point", () => {
    for (const event of ["disconnect", "disconnecting", "error", "connect_error"]) {
      const found = entriesOf(
        "src/gateway.ts",
        `
          import type { Socket } from "socket.io";
          export function register(socket: Socket) {
            socket.on("${event}", (reason) => log(reason));
          }
        `
      );
      assert.deepEqual(found, [], `${event} is raised by the library, not composed by the client`);
    }
  });

  test("an unrelated emitter in a gateway file is not a socket", () => {
    const found = entriesOf(
      "src/gateway.ts",
      `
        import { Server } from "socket.io";
        const io = new Server(httpServer);
        const bus = new EventEmitter();
        bus.on("import:finished", (result) => notify(result));
        io.on("connection", (socket) => socket.join("all"));
      `
    );
    assert.deepEqual(addresses(found), ["CONNECT connection"], "the emitter's event is nobody's message");
  });

  test("the HTTP server's own connection event is not a Socket.IO connection", () => {
    const found = entriesOf(
      "src/server.ts",
      `
        import { Server } from "socket.io";
        const io = new Server(httpServer);
        httpServer.on("connection", (raw) => raw.setNoDelay(true));
      `
    );
    assert.deepEqual(found, [], "a TCP socket is not a client's message channel");
  });

  test("the browser half of the application is never claimed", () => {
    const found = entriesOf(
      "src/client/live.ts",
      `
        import { io } from "socket.io-client";
        const socket = io("https://desk.example.com/agents");
        socket.on("conversation:updated", (conversation) => store.apply(conversation));
        socket.onAny((event, payload) => trace(event, payload));
      `
    );
    assert.deepEqual(found, [], "a client receives what the server sent, which no caller chose");
  });

  test("a file that only mentions the library in prose is not a gateway", () => {
    const file = parsed("src/notes.ts", `// the plan is to move this onto socket.io one day\nexport const notes = 1;`);
    assert.equal(realtimeAdapter.applies(file), false);
  });

  /* ================================================================== ws */

  test("the ws connection handler seeds the upgrade request and trusts the socket", () => {
    const found = entriesOf(
      "src/ws.ts",
      `
        import { WebSocketServer } from "ws";
        const wss = new WebSocketServer({ port: 8080 });
        wss.on("connection", (ws, request) => {
          ws.on("message", (data, isBinary) => {
            const command = JSON.parse(String(data));
            run(command.name);
          });
        });
      `
    );
    assert.deepEqual(addresses(found), ["CONNECT connection", "MESSAGE message"]);

    const connection = at(found, "CONNECT connection");
    assert.deepEqual(seedNames(connection), ["request"]);
    assert.equal(connection.seeds[0].origin, "request (HTTP request that opened the connection)");
    assert.deepEqual(connection.trustedParameters, ["ws"]);

    const message = at(found, "MESSAGE message");
    assert.deepEqual(seedNames(message), ["data"], "isBinary is a property of the frame, not a value the client composed");
    assert.equal(message.seeds[0].origin, "data (payload sent by the connected client)");
  });

  test("the older server spelling is the same server", () => {
    const found = entriesOf(
      "src/ws.js",
      `
        const WebSocket = require("ws");
        const server = new WebSocket.Server({ noServer: true });
        server.on("connection", (client, req) => {
          client.on("message", (raw) => dispatch(JSON.parse(raw)));
        });
      `
    );
    assert.deepEqual(addresses(found), ["CONNECT connection", "MESSAGE message"]);
    assert.deepEqual(seedNames(at(found, "CONNECT connection")), ["req"]);
    assert.deepEqual(seedNames(at(found, "MESSAGE message")), ["raw"]);
  });

  test("a socket typed by the library is recognised without a connection handler above it", () => {
    const found = entriesOf(
      "src/ws/commands.ts",
      `
        import type { WebSocket } from "ws";
        export function attach(client: WebSocket) {
          client.on("message", (payload) => dispatch(JSON.parse(String(payload))));
        }
      `
    );
    assert.deepEqual(addresses(found), ["MESSAGE message"]);
    assert.deepEqual(seedNames(found[0]), ["payload"]);
  });

  test("the standard event API delivers the message as an event object", () => {
    const found = entriesOf(
      "src/ws.ts",
      `
        import { WebSocketServer } from "ws";
        const wss = new WebSocketServer({ port: 8080 });
        wss.on("connection", (ws) => {
          ws.addEventListener("message", (event) => {
            run(JSON.parse(event.data).name);
          });
        });
      `
    );
    assert.deepEqual(addresses(found), ["CONNECT connection", "MESSAGE message"]);
    const message = at(found, "MESSAGE message");
    assert.deepEqual(seedNames(message), ["event"]);
    assert.equal(message.seeds[0].origin, "event (message sent by the connected client)");
  });

  test("a runtime that answers the upgrade itself hands back the client's socket", () => {
    const found = entriesOf(
      "src/ws.ts",
      `
        Deno.serve((request) => {
          const { socket, response } = Deno.upgradeWebSocket(request);
          socket.onmessage = (event) => {
            const command = JSON.parse(event.data);
            run(command.name);
          };
          return response;
        });
      `
    );
    assert.deepEqual(addresses(found), ["MESSAGE message"]);
    assert.deepEqual(seedNames(found[0]), ["event"]);
    assert.equal(found[0].seeds[0].origin, "event (message sent by the connected client)");
  });

  test("an outbound client connection is not an inbound one", () => {
    const found = entriesOf(
      "src/feed.ts",
      `
        import WebSocket from "ws";
        const upstream = new WebSocket("wss://prices.example.com/feed");
        upstream.on("message", (quote) => cache.set(JSON.parse(quote).symbol, quote));
      `
    );
    assert.deepEqual(found, [], "the peer here is the service this process dialled, not a caller");
  });

  test("a thread's message port is not a socket", () => {
    const found = entriesOf(
      "src/worker.js",
      `
        const { parentPort } = require("node:worker_threads");
        parentPort.on("message", (job) => run(job.name));
      `
    );
    assert.deepEqual(found, [], "the queue adapter owns thread messaging, and a thread is not a connected client");
  });

  /* ==================================================== BroadcastChannel */

  test("a broadcast channel is addressed by its own name", () => {
    const found = entriesOf(
      "src/sync.ts",
      `
        const channel = new BroadcastChannel("imports");
        channel.onmessage = (event) => {
          applyImport(event.data.path);
        };
      `
    );
    assert.deepEqual(addresses(found), ["MESSAGE imports"]);
    assert.deepEqual(seedNames(found[0]), ["event"]);
    assert.equal(found[0].seeds[0].origin, "event (message posted on the broadcast channel)");
  });

  test("the listener form of the same channel is the same entry point", () => {
    const found = entriesOf(
      "src/sync.ts",
      `
        const channel = new BroadcastChannel("imports");
        channel.addEventListener("message", ({ data }) => applyImport(data.path));
      `
    );
    assert.deepEqual(addresses(found), ["MESSAGE imports"]);
    assert.deepEqual(seedNames(found[0]), ["data"]);
  });

  test("a channel whose name is computed is still a channel", () => {
    const found = entriesOf(
      "src/sync.ts",
      `
        const channel = new BroadcastChannel(channelNameFor(tenant));
        channel.onmessage = (event) => applyImport(event.data.path);
      `
    );
    assert.deepEqual(addresses(found), ["MESSAGE broadcast"]);
    assert.deepEqual(seedNames(found[0]), ["event"]);
  });

  test("a server-sent event stream is a client subscription and is never claimed", () => {
    const found = entriesOf(
      "src/live.ts",
      `
        const stream = new EventSource("/events/deployments");
        stream.onmessage = (event) => render(JSON.parse(event.data));
      `
    );
    assert.deepEqual(found, [], "the data on an EventSource is the application's own output");
  });

  test("a server-sent events endpoint belongs to whichever adapter owns its route", () => {
    const file = parsed(
      "src/sse/deployments.ts",
      `
        export function stream(request: Request): Response {
          const body = new ReadableStream({
            start(controller) {
              controller.enqueue(encoder.encode("data: ready\\n\\n"));
            }
          });
          return new Response(body, { headers: { "content-type": "text/event-stream" } });
        }
      `
    );
    assert.equal(realtimeAdapter.applies(file), false, "an SSE endpoint is an ordinary HTTP handler");
  });
}
