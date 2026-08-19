"use server";

import { cookies } from "next/headers";
import { revalidatePath } from "next/cache";
import { eq } from "drizzle-orm";

import { db } from "@/lib/db";
import { accounts } from "@/db/schema";
import { getSessionByToken } from "@/lib/session";
import { deleteAvatarObject } from "@/lib/storage";

const MAX_HEADLINE = 120;

async function currentSession() {
  const cookieStore = await cookies();
  return getSessionByToken(cookieStore.get("mq_session")?.value ?? "");
}

export async function updateAccount(formData: FormData) {
  const session = await currentSession();
  if (!session) {
    return { ok: false as const, message: "Sign in to continue" };
  }

  const displayName = String(formData.get("displayName") ?? "").trim();
  const headline = String(formData.get("headline") ?? "").trim();
  const city = String(formData.get("city") ?? "").trim();

  if (!displayName) {
    return { ok: false as const, message: "A display name is required" };
  }

  if (headline.length > MAX_HEADLINE) {
    return { ok: false as const, message: "Keep the headline under 120 characters" };
  }

  await db
    .update(accounts)
    .set({ displayName, headline, city, updatedAt: new Date() })
    .where(eq(accounts.userId, session.userId));

  revalidatePath("/settings/account");
  return { ok: true as const };
}

export async function removeAccountAvatar() {
  const session = await currentSession();
  if (!session) {
    return { ok: false as const, message: "Sign in to continue" };
  }

  const account = await db.query.accounts.findFirst({
    where: eq(accounts.userId, session.userId),
    columns: { avatarKey: true },
  });

  if (account?.avatarKey) {
    await deleteAvatarObject(account.avatarKey);
  }

  await db
    .update(accounts)
    .set({ avatarKey: null, updatedAt: new Date() })
    .where(eq(accounts.userId, session.userId));

  revalidatePath("/settings/account");
  return { ok: true as const };
}
