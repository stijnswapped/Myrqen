import { Server } from "socket.io";
import { verifySocketToken } from "../lib/tokens";
import { registerConversationHandlers } from "./conversations";
import { registerContactHandlers } from "./contacts";

export function createGateway(httpServer: import("node:http").Server): Server {
  const io = new Server(httpServer, { cors: { origin: "https://desk.example.com" } });

  const agents = io.of("/agents");

  // Every socket carries a tenant from the handshake token. Handlers must never
  // read a tenant from the message body.
  agents.use(async (socket, next) => {
    try {
      const claims = await verifySocketToken(socket.handshake.auth?.token);
      socket.data.tenantId = claims.tenantId;
      socket.data.agentId = claims.sub;
      next();
    } catch (error) {
      next(new Error("unauthorized"));
    }
  });

  agents.on("connection", (socket) => {
    registerConversationHandlers(socket);
    registerContactHandlers(socket);
  });

  return io;
}
