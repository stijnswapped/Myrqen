import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { and, eq } from "drizzle-orm";

import { db } from "@/lib/db";
import { memberships, users } from "@/db/schema";
import { getSessionByToken } from "@/lib/session";
import { sendMembershipEmail } from "@/lib/mailer";

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

  const roster = await db
    .select({
      userId: users.id,
      email: users.email,
      fullName: users.fullName,
      role: memberships.role,
      joinedAt: memberships.createdAt,
    })
    .from(memberships)
    .innerJoin(users, eq(users.id, memberships.userId))
    .where(and(eq(memberships.teamId, teamId), eq(memberships.teamId, session.teamId)));

  return NextResponse.json({ members: roster });
}

export async function POST(request: Request, { params }: RouteContext) {
  const { teamId } = await params;
  const payload = (await request.json()) as { email?: string; role?: Role };
  const email = payload.email?.trim().toLowerCase();
  const role = payload.role ?? "viewer";

  if (!email || !ROLES.includes(role)) {
    return NextResponse.json({ error: "An email and a valid role are required" }, { status: 400 });
  }

  const invitee = await db.query.users.findFirst({
    where: eq(users.email, email),
    columns: { id: true, email: true, fullName: true },
  });

  if (!invitee) {
    return NextResponse.json({ error: "No account uses that email" }, { status: 404 });
  }

  const [membership] = await db
    .insert(memberships)
    .values({ teamId, userId: invitee.id, role })
    .onConflictDoUpdate({
      target: [memberships.teamId, memberships.userId],
      set: { role },
    })
    .returning({ id: memberships.id, role: memberships.role });

  await sendMembershipEmail(invitee.email, { teamId, role: membership.role });

  return NextResponse.json({ membership }, { status: 201 });
}
