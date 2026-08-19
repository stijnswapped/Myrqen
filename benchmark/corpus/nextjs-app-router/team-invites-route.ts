import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { and, eq } from "drizzle-orm";

import { db } from "@/lib/db";
import { invitations, users } from "@/db/schema";
import { getSessionByToken } from "@/lib/session";
import { sendInvitationEmail } from "@/lib/mailer";
import { newInviteToken } from "@/lib/tokens";

type RouteContext = { params: Promise<{ teamId: string }> };

const ROLES = ["viewer", "editor", "admin"] as const;
type Role = (typeof ROLES)[number];

export async function GET(request: Request, { params }: RouteContext) {
  const { teamId } = await params;
  const cookieStore = await cookies();
  const session = await getSessionByToken(cookieStore.get("mq_session")?.value ?? "");

  if (!session) {
    return NextResponse.json({ error: "Sign in to continue" }, { status: 401 });
  }

  const pending = await db
    .select({
      id: invitations.id,
      email: invitations.email,
      role: invitations.role,
      invitedAt: invitations.createdAt,
    })
    .from(invitations)
    .where(and(eq(invitations.teamId, teamId), eq(invitations.teamId, session.teamId)));

  return NextResponse.json({ invitations: pending });
}

export async function POST(request: Request, { params }: RouteContext) {
  const { teamId } = await params;
  const cookieStore = await cookies();
  const session = await getSessionByToken(cookieStore.get("mq_session")?.value ?? "");

  if (!session) {
    return NextResponse.json({ error: "Sign in to continue" }, { status: 401 });
  }

  if (session.teamId !== teamId) {
    return NextResponse.json({ error: "Team not found" }, { status: 404 });
  }

  const payload = (await request.json()) as { email?: string; role?: Role };
  const email = payload.email?.trim().toLowerCase();
  const role = payload.role ?? "viewer";

  if (!email || !ROLES.includes(role)) {
    return NextResponse.json({ error: "An email and a valid role are required" }, { status: 400 });
  }

  const existing = await db.query.users.findFirst({
    where: eq(users.email, email),
    columns: { id: true },
  });

  const [invitation] = await db
    .insert(invitations)
    .values({ teamId, email, role, token: newInviteToken(), invitedBy: session.userId })
    .returning({ id: invitations.id, email: invitations.email, role: invitations.role });

  await sendInvitationEmail(email, { teamId, role, alreadyRegistered: Boolean(existing) });

  return NextResponse.json({ invitation }, { status: 201 });
}
