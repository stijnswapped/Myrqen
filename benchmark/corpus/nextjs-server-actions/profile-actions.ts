"use server";

import { cookies } from "next/headers";
import { revalidatePath } from "next/cache";
import { eq } from "drizzle-orm";

import { db } from "@/lib/db";
import { profiles } from "@/db/schema";
import { getSessionByToken } from "@/lib/session";
import { deleteAvatarObject } from "@/lib/storage";

const MAX_HEADLINE = 120;

export async function updateProfile(formData: FormData) {
  const userId = String(formData.get("userId") ?? "");
  const displayName = String(formData.get("displayName") ?? "").trim();
  const headline = String(formData.get("headline") ?? "").trim();
  const city = String(formData.get("city") ?? "").trim();

  if (!userId || !displayName) {
    return { ok: false as const, message: "A display name is required" };
  }

  if (headline.length > MAX_HEADLINE) {
    return { ok: false as const, message: "Keep the headline under 120 characters" };
  }

  await db
    .update(profiles)
    .set({ displayName, headline, city, updatedAt: new Date() })
    .where(eq(profiles.userId, userId));

  revalidatePath("/settings/profile");
  return { ok: true as const };
}

export async function removeAvatar() {
  const cookieStore = await cookies();
  const session = await getSessionByToken(cookieStore.get("mq_session")?.value ?? "");

  if (!session) {
    return { ok: false as const, message: "Sign in to continue" };
  }

  const profile = await db.query.profiles.findFirst({
    where: eq(profiles.userId, session.userId),
    columns: { avatarKey: true },
  });

  if (profile?.avatarKey) {
    await deleteAvatarObject(profile.avatarKey);
  }

  await db
    .update(profiles)
    .set({ avatarKey: null, updatedAt: new Date() })
    .where(eq(profiles.userId, session.userId));

  revalidatePath("/settings/profile");
  return { ok: true as const };
}
