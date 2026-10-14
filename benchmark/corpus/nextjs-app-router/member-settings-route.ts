import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { eq } from "drizzle-orm";
import { z } from "zod";

import { db } from "@/lib/db";
import { users } from "@/db/schema";
import { getSessionByToken } from "@/lib/session";

const SettingsPatch = z
  .object({
    displayName: z.string().trim().min(1).max(80),
    avatarUrl: z.string().url().max(500),
    timeZone: z.string().max(64),
    notificationEmail: z.string().email(),
  })
  .partial()
  .strict();

// PATCH /api/me/settings
// The account settings form saves whichever fields the user edited: display
// name, avatar, time zone, notification email. Nothing else is writable here.
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

  const parsed = SettingsPatch.safeParse(await request.json());
  if (!parsed.success) {
    return NextResponse.json({ error: "Invalid settings" }, { status: 400 });
  }

  const [updated] = await db
    .update(users)
    .set(parsed.data)
    .where(eq(users.id, session.userId))
    .returning({ id: users.id, displayName: users.displayName, role: users.role });

  return NextResponse.json({ user: updated });
}
