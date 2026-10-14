import { parse as parseCookie } from "cookie";
import type { NextFunction, Request, Response } from "express";
import { pool } from "../db/postgres.js";

const SESSION_COOKIE = "deskline_session";

export interface AgentContext {
  id: string;
  orgId: string;
  role: "agent" | "lead" | "admin";
}

export interface AgentRequest extends Request {
  agent: AgentContext;
}

/**
 * EventSource cannot send an Authorization header, so the desk cookie is the
 * only credential a stream request can carry. The token is stored hashed; the
 * comparison happens in Postgres against the digest, never against the raw
 * value.
 */
export async function requireAgent(req: Request, res: Response, next: NextFunction): Promise<void> {
  const token = parseCookie(req.headers.cookie ?? "")[SESSION_COOKIE];
  if (!token) {
    res.status(401).json({ error: "unauthenticated" });
    return;
  }

  try {
    const { rows } = await pool.query(
      `SELECT a.id, a.org_id, a.role
         FROM desk_sessions s
         JOIN agents a ON a.id = s.agent_id
        WHERE s.token_hash = encode(digest($1, 'sha256'), 'hex')
          AND s.expires_at > now()`,
      [token]
    );

    if (rows.length === 0) {
      res.status(401).json({ error: "unauthenticated" });
      return;
    }

    (req as AgentRequest).agent = { id: rows[0].id, orgId: rows[0].org_id, role: rows[0].role };
    next();
  } catch (error) {
    next(error);
  }
}
