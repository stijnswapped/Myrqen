import { getWebRequest } from "@tanstack/start/server";
import { db } from "./db";

export type Role = "requester" | "approver" | "finance" | "admin";

export interface Session {
  userId: string;
  tenantId: string;
  roles: Role[];
}

export class HttpError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

/** Resolves the signed session cookie. Throws 401 when there isn't one. */
export async function requireSession(): Promise<Session> {
  const request = getWebRequest();
  const token = request.headers.get("cookie")?.match(/procure_session=([^;]+)/)?.[1];
  if (!token) throw new HttpError(401, "Sign in to continue.");

  const row = await db.session.findFirst({
    where: { tokenHash: hash(token), expiresAt: { gt: new Date() } },
    select: { userId: true, tenantId: true, roles: true },
  });
  if (!row) throw new HttpError(401, "Your session has expired.");
  return { userId: row.userId, tenantId: row.tenantId, roles: row.roles as Role[] };
}

function hash(token: string): string {
  return require("node:crypto").createHash("sha256").update(token).digest("hex");
}
