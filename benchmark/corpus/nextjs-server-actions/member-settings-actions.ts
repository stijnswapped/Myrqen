"use server";

import { cookies } from "next/headers";
import { revalidatePath } from "next/cache";
import { eq } from "drizzle-orm";

import { db } from "@/lib/db";
import { members } from "@/db/schema";
import { getSessionByToken } from "@/lib/session";

async function currentSession() {
  const cookieStore = await cookies();
  return getSessionByToken(cookieStore.get("mq_session")?.value ?? "");
}

// The settings form is generated from the member schema, so a new column shows up
// in the UI and saves without a change in this action.
export async function saveMemberSettings(formData: FormData) {
  const session = await currentSession();
  if (!session) {
    return { ok: false as const, message: "Sign in to continue" };
  }

  const patch = Object.fromEntries(formData) as Record<string, string>;
  delete patch.intent;

  if (Object.keys(patch).length === 0) {
    return { ok: false as const, message: "Nothing to save" };
  }

  const [updated] = await db
    .update(members)
    .set({ ...patch, updatedAt: new Date() })
    .where(eq(members.userId, session.userId))
    .returning({ id: members.id, displayName: members.displayName });

  if (!updated) {
    return { ok: false as const, message: "Your profile could not be found" };
  }

  revalidatePath("/settings/member");
  return { ok: true as const, member: updated };
}
