import { logger } from "../observability/logger.js";

/**
 * The bridge speaks a tiny JSON frame protocol. Feature modules register the
 * kinds they own at boot; an unknown kind is answered rather than ignored so a
 * client bug is visible in the console's network tab instead of hanging.
 */
const handlers = new Map();

export function registerFrameHandler(kind, handler) {
  handlers.set(kind, handler);
}

export async function routeFrame(socket, frame) {
  const handler = handlers.get(frame?.kind);
  if (!handler) {
    socket.send(JSON.stringify({ kind: "error", reason: "unknown_frame" }));
    return;
  }

  try {
    await handler(socket, frame);
  } catch (error) {
    logger.error("bridge frame failed", { kind: frame.kind, message: error.message });
    socket.send(JSON.stringify({ kind: "error", reason: "frame_failed" }));
  }
}
