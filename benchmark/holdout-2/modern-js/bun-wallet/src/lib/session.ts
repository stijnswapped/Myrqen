import { createHash } from "node:crypto";
import { one } from "./db";

export interface Session {
  userId: string;
  walletId: string;
}

export async function sessionFor(request: Request): Promise<Session | null> {
  const header = request.headers.get("authorization") ?? "";
  if (!header.startsWith("Bearer ")) return null;
  const hash = createHash("sha256").update(header.slice(7)).digest("hex");
  return one<Session>(
    `SELECT user_id AS "userId", wallet_id AS "walletId"
       FROM sessions WHERE token_hash = $1 AND expires_at > now()`,
    [hash],
  );
}

export function hashCode(code: string): string {
  return createHash("sha256").update(code.trim().toUpperCase()).digest("hex");
}
