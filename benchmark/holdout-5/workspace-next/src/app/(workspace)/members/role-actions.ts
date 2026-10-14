"use server";

import { revalidatePath } from "next/cache";
import { z } from "zod";
import { prisma } from "@/lib/prisma";
import { ROLE_RANK, isAtLeast, requireMembership, requireSession, type Role } from "@/lib/auth";

export interface RoleChangeResult {
  ok: boolean;
  message?: string;
}

const roleChangeSchema = z.object({
  workspaceId: z.string().cuid(),
  memberId: z.string().cuid(),
  role: z.enum(["owner", "admin", "editor", "viewer"]),
});

/**
 * Change an existing member's role from the members table.
 *
 * Two rules, both enforced here: the actor has to be an admin or owner, and no
 * one can hand out a role above the one they hold themselves - otherwise an
 * admin could promote a second account to owner and take over billing.
 */
export async function changeMemberRole(formData: FormData): Promise<RoleChangeResult> {
  const session = await requireSession();

  const parsed = roleChangeSchema.safeParse(Object.fromEntries(formData.entries()));
  if (!parsed.success) {
    return { ok: false, message: "Pick a member and a role." };
  }
  const { workspaceId, memberId, role } = parsed.data;

  let actor;
  try {
    actor = await requireMembership(session.user.id, workspaceId);
  } catch {
    return { ok: false, message: "You are not a member of this workspace." };
  }
  if (!isAtLeast(actor.role, "admin")) {
    return { ok: false, message: "Only admins and owners can change roles." };
  }

  const target = await prisma.workspaceMember.findFirst({
    where: { id: memberId, workspaceId: actor.workspaceId },
    select: { id: true, userId: true, role: true },
  });
  if (!target) {
    return { ok: false, message: "That member is not in this workspace." };
  }

  const requestedRole = role as Role;
  if (ROLE_RANK[requestedRole] > ROLE_RANK[actor.role]) {
    return { ok: false, message: "You cannot grant a role above your own." };
  }
  if (ROLE_RANK[target.role as Role] > ROLE_RANK[actor.role]) {
    return { ok: false, message: "You cannot change the role of an owner." };
  }

  if (target.role === "owner" && requestedRole !== "owner") {
    const owners = await prisma.workspaceMember.count({
      where: { workspaceId: actor.workspaceId, role: "owner" },
    });
    if (owners <= 1) {
      return { ok: false, message: "A workspace needs at least one owner." };
    }
  }

  await prisma.workspaceMember.update({
    where: { id: target.id },
    data: { role: requestedRole },
  });

  await prisma.activityEvent.create({
    data: {
      workspaceId: actor.workspaceId,
      actorId: session.user.id,
      kind: "member.role_changed",
      metadata: { memberId: target.id, from: target.role, to: requestedRole },
    },
  });

  revalidatePath("/members");
  return { ok: true };
}
