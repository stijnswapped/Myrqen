import { createHash } from "node:crypto";
import { sql } from "./db";

export interface Session {
  userId: string;
  accountId: string;
}

export async function sessionFromCookie(request: Request): Promise<Session | null> {
  const token = request.headers.get("cookie")?.match(/pulse_session=([^;]+)/)?.[1];
  if (!token) return null;
  const hash = createHash("sha256").update(decodeURIComponent(token)).digest("hex");
  const rows = await sql<Session>(
    `SELECT user_id AS "userId", account_id AS "accountId"
       FROM sessions WHERE token_hash = $1 AND expires_at > now()`,
    [hash],
  );
  return rows[0] ?? null;
}
