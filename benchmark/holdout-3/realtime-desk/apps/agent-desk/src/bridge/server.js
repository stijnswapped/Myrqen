import { WebSocketServer } from "ws";
import { verifyHandshakeTicket } from "./handshake.js";
import { logger } from "../observability/logger.js";
import { routeFrame } from "./router.js";

/**
 * The widget bridge. This service predates the TypeScript migration and is
 * deliberately dependency-light: it terminates the raw WebSocket, hands frames
 * to the router and does nothing else. Everything stateful lives behind the
 * frame handlers.
 */
const BRIDGE_PATH = "/bridge/v1";
const MAX_FRAME_BYTES = 64 * 1024;
const IDLE_TIMEOUT_MS = 60_000;

export const bridge = new WebSocketServer({ noServer: true, maxPayload: MAX_FRAME_BYTES });

bridge.on("connection", (socket) => {
  socket.isAlive = true;
  socket.on("pong", () => {
    socket.isAlive = true;
  });

  socket.on("message", async (raw) => {
    let frame;
    try {
      frame = JSON.parse(raw.toString("utf8"));
    } catch {
      socket.send(JSON.stringify({ kind: "error", reason: "bad_json" }));
      return;
    }
    await routeFrame(socket, frame);
  });

  socket.on("error", (error) => {
    logger.warn("bridge socket error", { message: error.message });
  });
});

// A browser that goes to sleep leaves a half-open socket behind; the ping
// sweep is what actually reclaims those file descriptors.
const sweep = setInterval(() => {
  for (const socket of bridge.clients) {
    if (!socket.isAlive) {
      socket.terminate();
      continue;
    }
    socket.isAlive = false;
    socket.ping();
  }
}, IDLE_TIMEOUT_MS);
sweep.unref();

export function attachBridge(server) {
  server.on("upgrade", (request, socket, head) => {
    let url;
    try {
      url = new URL(request.url, `http://${request.headers.host ?? "bridge.internal"}`);
    } catch {
      socket.destroy();
      return;
    }

    if (url.pathname !== BRIDGE_PATH) {
      socket.destroy();
      return;
    }

    // The console cannot set a header on a handshake, so the credential rides
    // on the query string — but it is a signed, thirty-second ticket minted by
    // the desk API, not a claim the client gets to make about itself.
    const session = verifyHandshakeTicket(url.searchParams.get("t"));
    if (!session) {
      logger.warn("bridge upgrade rejected", { remote: request.socket.remoteAddress });
      socket.write("HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n");
      socket.destroy();
      return;
    }

    bridge.handleUpgrade(request, socket, head, (ws) => {
      ws.session = { ...session, connectedAt: Date.now() };

      logger.info("bridge connected", { agentId: ws.session.agentId, orgId: ws.session.orgId });
      bridge.emit("connection", ws, request);
    });
  });
}
