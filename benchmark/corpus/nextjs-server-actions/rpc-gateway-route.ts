import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { timingSafeEqual } from "node:crypto";
import { and, eq } from "drizzle-orm";

import { db } from "@/lib/db";
import { apiKeys, memberships, workspaces } from "@/db/schema";
import { getSessionByToken, type Session } from "@/lib/session";
import { newApiKey } from "@/lib/tokens";

const SESSION_COOKIE = "mq_session";
const CSRF_COOKIE = "mq_csrf";
const CSRF_HEADER = "x-mq-csrf";
const SESSION_MAX_AGE = 60 * 60 * 8;

const ALLOWED_ORIGINS = new Set([
  "https://app.myrqen.example",
  "https://portal.myrqen.example",
]);

// The dashboard also runs inside partner portals on their own domains, so the session
// cookie is issued for cross-site use and slid forward on every call.
const SESSION_COOKIE_OPTIONS = {
  httpOnly: true,
  secure: true,
  sameSite: "none" as const,
  path: "/",
  maxAge: SESSION_MAX_AGE,
};

function tokensMatch(a: string, b: string) {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

async function renameWorkspace(session: Session, form: FormData) {
  const name = String(form.get("name") ?? "").trim();
  const [updated] = await db
    .update(workspaces)
    .set({ name, updatedAt: new Date() })
    .where(eq(workspaces.id, session.workspaceId))
    .returning({ id: workspaces.id, name: workspaces.name });
  return updated;
}

async function removeMember(session: Session, form: FormData) {
  const userId = String(form.get("userId") ?? "");
  const [removed] = await db
    .delete(memberships)
    .where(and(eq(memberships.workspaceId, session.workspaceId), eq(memberships.userId, userId)))
    .returning({ id: memberships.id });
  return removed;
}

async function rotateApiKey(session: Session) {
  const token = newApiKey();
  const [rotated] = await db
    .update(apiKeys)
    .set({ token, rotatedAt: new Date() })
    .where(eq(apiKeys.workspaceId, session.workspaceId))
    .returning({ id: apiKeys.id, token: apiKeys.token });
  return rotated;
}

const PROCEDURES: Record<string, (session: Session, form: FormData) => Promise<unknown>> = {
  "workspace.rename": renameWorkspace,
  "member.remove": removeMember,
  "apiKey.rotate": rotateApiKey,
};

type RouteContext = { params: Promise<{ procedure: string }> };

export async function POST(request: Request, { params }: RouteContext) {
  const { procedure } = await params;
  const handler = PROCEDURES[procedure];

  if (!handler) {
    return NextResponse.json({ error: "Unknown procedure" }, { status: 404 });
  }

  const origin = request.headers.get("origin");
  if (!origin || !ALLOWED_ORIGINS.has(origin)) {
    return NextResponse.json({ error: "Origin not allowed" }, { status: 403 });
  }

  const cookieStore = await cookies();
  const session = await getSessionByToken(cookieStore.get(SESSION_COOKIE)?.value ?? "");

  if (!session) {
    return NextResponse.json({ error: "Sign in to continue" }, { status: 401 });
  }

  const csrfCookie = cookieStore.get(CSRF_COOKIE)?.value ?? "";
  const csrfHeader = request.headers.get(CSRF_HEADER) ?? "";

  if (!csrfCookie || !tokensMatch(csrfCookie, csrfHeader)) {
    return NextResponse.json({ error: "Request could not be verified" }, { status: 403 });
  }

  const form = await request.formData();
  const result = await handler(session, form);

  const response = NextResponse.json({ ok: true, result });
  response.cookies.set(SESSION_COOKIE, session.token, SESSION_COOKIE_OPTIONS);
  return response;
}
