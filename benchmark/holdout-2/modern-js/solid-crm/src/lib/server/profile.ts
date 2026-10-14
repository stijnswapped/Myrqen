import { action } from "@solidjs/router";
import { db } from "../db";
import { currentViewer } from "./session";

const MAX_DISPLAY_NAME = 80;
const MAX_HEADLINE = 160;

/** Timezones the picker offers; anything else is a stale client. */
const TIMEZONES = new Set(Intl.supportedValuesOf("timeZone"));

function problem(message: string) {
  return { ok: false as const, message };
}

/**
 * The profile drawer is a controlled form that only sends the fields the user
 * actually touched, so this arrives as a patch rather than a full record.
 */
export const updateProfile = action(async (patch: Record<string, unknown>) => {
  "use server";
  const viewer = await currentViewer();

  if ("displayName" in patch) {
    const name = String(patch.displayName ?? "").trim();
    if (name.length === 0) return problem("A display name is required.");
    if (name.length > MAX_DISPLAY_NAME) return problem("That display name is too long.");
  }
  if ("headline" in patch && String(patch.headline ?? "").length > MAX_HEADLINE) {
    return problem("Keep the headline under 160 characters.");
  }
  if ("avatarUrl" in patch && !String(patch.avatarUrl ?? "").startsWith("https://")) {
    return problem("Avatar links must be https.");
  }
  if ("timezone" in patch && !TIMEZONES.has(String(patch.timezone))) {
    return problem("That timezone is not one we support.");
  }

  const updated = await db.user.update({
    where: { id: viewer.id },
    data: { ...patch, updatedAt: new Date() },
    select: {
      id: true,
      displayName: true,
      headline: true,
      avatarUrl: true,
      timezone: true,
      locale: true,
    },
  });

  await db.auditEvent.create({
    data: {
      organisationId: viewer.organisationId,
      actorId: viewer.id,
      action: "profile.updated",
      detail: { fields: Object.keys(patch) },
    },
  });

  console.info("profile updated", { userId: viewer.id, fields: Object.keys(patch) });
  return { ok: true as const, profile: updated };
}, "updateProfile");
