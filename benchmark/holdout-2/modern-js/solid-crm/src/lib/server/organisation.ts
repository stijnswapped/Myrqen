import { action } from "@solidjs/router";
import { db } from "../db";
import { assertOwner, currentViewer } from "./session";

const MAX_DISPLAY_NAME = 80;
const MAX_STRAPLINE = 160;

/** Timezones the picker offers; anything else is a stale client. */
const TIMEZONES = new Set(Intl.supportedValuesOf("timeZone"));

/** The only columns this form owns. Billing plan and seat count are not among them. */
const EDITABLE = ["displayName", "strapline", "logoUrl", "timezone", "locale"] as const;

function problem(message: string) {
  return { ok: false as const, message };
}

/**
 * The organisation settings form is controlled and only sends what changed, so
 * this arrives as a patch rather than a full record.
 */
export const updateOrganisation = action(async (patch: Record<string, unknown>) => {
  "use server";
  const viewer = await currentViewer();
  await assertOwner(viewer);

  if ("displayName" in patch) {
    const name = String(patch.displayName ?? "").trim();
    if (name.length === 0) return problem("A display name is required.");
    if (name.length > MAX_DISPLAY_NAME) return problem("That display name is too long.");
  }
  if ("strapline" in patch && String(patch.strapline ?? "").length > MAX_STRAPLINE) {
    return problem("Keep the strapline under 160 characters.");
  }
  if ("logoUrl" in patch && !String(patch.logoUrl ?? "").startsWith("https://")) {
    return problem("Logo links must be https.");
  }
  if ("timezone" in patch && !TIMEZONES.has(String(patch.timezone))) {
    return problem("That timezone is not one we support.");
  }

  const changes: Record<string, unknown> = {};
  for (const field of EDITABLE) {
    if (field in patch) changes[field] = patch[field];
  }

  const updated = await db.organisation.update({
    where: { id: viewer.organisationId },
    data: { ...changes, updatedAt: new Date() },
    select: {
      id: true,
      displayName: true,
      strapline: true,
      logoUrl: true,
      timezone: true,
      locale: true,
    },
  });

  await db.auditEvent.create({
    data: {
      organisationId: viewer.organisationId,
      actorId: viewer.id,
      action: "organisation.updated",
      detail: { fields: Object.keys(changes) },
    },
  });

  console.info("organisation updated", { id: viewer.organisationId, fields: Object.keys(changes) });
  return { ok: true as const, organisation: updated };
}, "updateOrganisation");
