import { createCookieSessionStorage, redirect } from "react-router";
import { db, type UserRole } from "./db/client";

const sessionSecret = process.env.SESSION_SECRET;

if (!sessionSecret) {
  throw new Error("SESSION_SECRET is required to boot the ATS server");
}

/**
 * Signed cookie session. We deliberately keep only the user id in the cookie
 * and re-read the user row on every request so that deactivating an account in
 * the admin console takes effect immediately instead of at cookie expiry.
 */
export const sessionStorage = createCookieSessionStorage({
  cookie: {
    name: "__ats_session",
    path: "/",
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    secrets: [sessionSecret],
    maxAge: 60 * 60 * 8,
  },
});

export interface SessionUser {
  id: string;
  email: string;
  fullName: string;
  role: UserRole;
}

export async function getSession(request: Request) {
  return sessionStorage.getSession(request.headers.get("Cookie"));
}

export async function getSessionUser(request: Request): Promise<SessionUser | null> {
  const session = await getSession(request);
  const userId = session.get("userId");

  if (typeof userId !== "string" || userId.length === 0) {
    return null;
  }

  const row = await db
    .selectFrom("users")
    .select(["id", "email", "full_name", "role"])
    .where("id", "=", userId)
    .where("is_active", "=", true)
    .executeTakeFirst();

  if (!row) {
    return null;
  }

  return { id: row.id, email: row.email, fullName: row.full_name, role: row.role };
}

export async function requireUser(request: Request): Promise<SessionUser> {
  const user = await getSessionUser(request);

  if (!user) {
    const url = new URL(request.url);
    throw redirect(`/sign-in?next=${encodeURIComponent(url.pathname + url.search)}`);
  }

  return user;
}

export async function requireRole(request: Request, allowed: UserRole[]): Promise<SessionUser> {
  const user = await requireUser(request);

  if (!allowed.includes(user.role)) {
    throw new Response("Forbidden", { status: 403 });
  }

  return user;
}

export async function commitUserSession(request: Request, userId: string) {
  const session = await getSession(request);
  session.set("userId", userId);
  return sessionStorage.commitSession(session);
}
