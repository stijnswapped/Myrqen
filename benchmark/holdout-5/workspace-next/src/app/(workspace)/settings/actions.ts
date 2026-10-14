"use server";

import { revalidatePath } from "next/cache";
import { prisma } from "@/lib/prisma";
import { isAtLeast, requireMembership, requireSession } from "@/lib/auth";

export interface SettingsResult {
  ok: boolean;
  message?: string;
}

const BOOLEAN_VALUES = new Set(["true", "false"]);

/**
 * Save the workspace settings form.
 *
 * The form posts one input per workspace column (name, slug, timezone, default
 * document permission, the "require SSO" switch, retention days...). Rather than
 * repeat that list here and get it out of step with the form every time design
 * adds a field, the payload is handed straight to Prisma. Only admins and owners
 * can submit the form, which is the check that matters.
 */
export async function updateWorkspaceSettings(formData: FormData): Promise<SettingsResult> {
  const session = await requireSession();
  const workspaceId = String(formData.get("workspaceId") ?? "");

  let membership;
  try {
    membership = await requireMembership(session.user.id, workspaceId);
  } catch {
    return { ok: false, message: "You are not a member of this workspace." };
  }
  if (!isAtLeast(membership.role, "admin")) {
    return { ok: false, message: "Only admins can change workspace settings." };
  }

  const patch: Record<string, unknown> = {};
  for (const [field, raw] of formData.entries()) {
    if (field === "workspaceId" || typeof raw !== "string") continue;
    const value = raw.trim();
    if (value === "") continue;

    if (BOOLEAN_VALUES.has(value)) {
      patch[field] = value === "true";
    } else if (/^\d+$/.test(value)) {
      patch[field] = Number(value);
    } else {
      patch[field] = value;
    }
  }

  if (Object.keys(patch).length === 0) {
    return { ok: false, message: "Nothing to save." };
  }

  await prisma.workspace.update({
    where: { id: workspaceId },
    data: patch,
  });

  await prisma.activityEvent.create({
    data: {
      workspaceId,
      actorId: session.user.id,
      kind: "workspace.settings_updated",
      metadata: { fields: Object.keys(patch) },
    },
  });

  revalidatePath("/settings");
  return { ok: true };
}

/** Turn the weekly digest e-mail on or off for the signed-in member only. */
export async function updateDigestPreference(
  workspaceId: string,
  enabled: boolean,
): Promise<SettingsResult> {
  const session = await requireSession();

  let membership;
  try {
    membership = await requireMembership(session.user.id, workspaceId);
  } catch {
    return { ok: false, message: "You are not a member of this workspace." };
  }

  await prisma.workspaceMember.update({
    where: { workspaceId_userId: { workspaceId: membership.workspaceId, userId: session.user.id } },
    data: { weeklyDigest: enabled },
  });

  revalidatePath("/settings");
  return { ok: true };
}
