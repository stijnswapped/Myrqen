import { logger } from "../../observability/logger.js";
import type { DeskSession, DeskSocket } from "../types.js";

type Next = (error?: Error) => void;

/**
 * Namespace-level role gate. It runs once per connection rather than once per
 * event, which is the point: a handler added to the namespace next quarter
 * inherits the check instead of having to remember it.
 */
export function requireDeskRole(...roles: DeskSession["role"][]) {
  const allowed = new Set(roles);

  return (socket: DeskSocket, next: Next): void => {
    const session = socket.data.session;

    if (!session) {
      next(new Error("unauthenticated"));
      return;
    }

    if (!allowed.has(session.role)) {
      logger.warn("desk role denied", {
        agentId: session.agentId,
        role: session.role,
        needed: [...allowed]
      });
      next(new Error("forbidden"));
      return;
    }

    next();
  };
}
