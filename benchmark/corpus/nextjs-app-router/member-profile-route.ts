import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { eq } from "drizzle-orm";

import { db } from "@/lib/db";
import { users } from "@/db/schema";
import { getSessionByToken } from "@/lib/session";

// PATCH /api/me
// The account settings form saves whichever fields the user edited: display
// name, avatar, time zone, notification email.
export async function PATCH(request: Request) {
  const cookieStore = await cookies();
  const sessionToken = cookieStore.get("mq_session")?.value;
  if (!sessionToken) {
    return NextResponse.json({ error: "Sign in to continue" }, { status: 401 });
  }

  const session = await getSessionByToken(sessionToken);
  if (!session) {
    return NextResponse.json({ error: "Your session has expired" }, { status: 401 });
  }

  const changes = await request.json();
  const [updated] = await db
    .update(users)
    .set(changes)
    .where(eq(users.id, session.userId))
    .returning({ id: users.id, displayName: users.displayName, role: users.role });

  return NextResponse.json({ user: updated });
}
