import { parse as parseCookie } from "cookie";
import { pool } from "../../db/postgres.js";
import type { DeskSocket } from "../types.js";

const SESSION_COOKIE = "deskline_session";

/**
 * Socket.IO middleware is per namespace and does not inherit from the main
 * namespace, so every namespace that carries privileged events registers this
 * itself. Forgetting it produces a connection with no socket.data.session,
 * which every handler then fails closed on.
 */
export async function authenticateSocket(socket: DeskSocket, next: (error?: Error) => void): Promise<void> {
  try {
    const token = parseCookie(socket.handshake.headers.cookie ?? "")[SESSION_COOKIE];
    if (!token) {
      next(new Error("unauthenticated"));
      return;
    }

    const { rows } = await pool.query(
      `SELECT a.id, a.org_id, a.role
         FROM desk_sessions s
         JOIN agents a ON a.id = s.agent_id
        WHERE s.token_hash = encode(digest($1, 'sha256'), 'hex')
          AND s.expires_at > now()`,
      [token]
    );

    if (rows.length === 0) {
      next(new Error("unauthenticated"));
      return;
    }

    socket.data.session = { agentId: rows[0].id, orgId: rows[0].org_id, role: rows[0].role };
    next();
  } catch {
    next(new Error("session_lookup_failed"));
  }
}
