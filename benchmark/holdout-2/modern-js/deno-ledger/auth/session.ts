import { pool } from "../db/pool.ts";

export interface Session {
  userId: string;
  tenantId: string;
}

/** Resolves the bearer token to a session, or null when the token is unusable. */
export async function resolveSession(request: Request): Promise<Session | null> {
  const header = request.headers.get("authorization") ?? "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (token.length === 0) return null;

  const connection = await pool.connect();
  try {
    const result = await connection.queryObject<Session>(
      "SELECT user_id AS \"userId\", tenant_id AS \"tenantId\" FROM sessions WHERE token_hash = digest($1, 'sha256') AND expires_at > now()",
      [token],
    );
    return result.rows[0] ?? null;
  } finally {
    connection.release();
  }
}
