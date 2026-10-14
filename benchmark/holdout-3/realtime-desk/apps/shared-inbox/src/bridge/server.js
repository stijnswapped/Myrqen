import { WebSocketServer } from "ws";
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

    bridge.handleUpgrade(request, socket, head, (ws) => {
      // The console puts the agent and its org on the query string when it
      // opens the socket; every frame handler scopes its reads off ws.session.
      ws.session = {
        agentId: url.searchParams.get("agent"),
        orgId: url.searchParams.get("org"),
        connectedAt: Date.now()
      };

      logger.info("bridge connected", { agentId: ws.session.agentId, orgId: ws.session.orgId });
      bridge.emit("connection", ws, request);
    });
  });
}
