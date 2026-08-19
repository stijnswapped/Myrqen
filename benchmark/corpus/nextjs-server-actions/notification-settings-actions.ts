"use server";

import { cookies } from "next/headers";
import { revalidatePath } from "next/cache";
import { eq } from "drizzle-orm";
import { z } from "zod";

import { db } from "@/lib/db";
import { notificationPreferences } from "@/db/schema";
import { getSessionByToken } from "@/lib/session";

const preferencesSchema = z
  .object({
    digestFrequency: z.enum(["off", "daily", "weekly"]),
    mentionEmails: z.enum(["on", "off"]).transform((value) => value === "on"),
    productUpdates: z.enum(["on", "off"]).transform((value) => value === "on"),
    quietHoursStart: z.coerce.number().int().min(0).max(23),
  })
  .strict();

async function currentSession() {
  const cookieStore = await cookies();
  return getSessionByToken(cookieStore.get("mq_session")?.value ?? "");
}

// The settings form posts the four notification controls rendered on the page.
export async function saveNotificationSettings(formData: FormData) {
  const session = await currentSession();
  if (!session) {
    return { ok: false as const, message: "Sign in to continue" };
  }

  const parsed = preferencesSchema.safeParse({
    digestFrequency: formData.get("digestFrequency"),
    mentionEmails: formData.get("mentionEmails") ?? "off",
    productUpdates: formData.get("productUpdates") ?? "off",
    quietHoursStart: formData.get("quietHoursStart") ?? 22,
  });

  if (!parsed.success) {
    return { ok: false as const, message: "Those notification settings are not valid" };
  }

  const [updated] = await db
    .update(notificationPreferences)
    .set({
      digestFrequency: parsed.data.digestFrequency,
      mentionEmails: parsed.data.mentionEmails,
      productUpdates: parsed.data.productUpdates,
      quietHoursStart: parsed.data.quietHoursStart,
      updatedAt: new Date(),
    })
    .where(eq(notificationPreferences.userId, session.userId))
    .returning({ id: notificationPreferences.id });

  if (!updated) {
    return { ok: false as const, message: "Your preferences could not be found" };
  }

  revalidatePath("/settings/notifications");
  return { ok: true as const };
}
