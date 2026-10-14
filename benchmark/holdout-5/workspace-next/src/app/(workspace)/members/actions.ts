"use server";

import { randomBytes } from "node:crypto";
import { revalidatePath } from "next/cache";
import { z } from "zod";
import { prisma } from "@/lib/prisma";
import { requireMembership, requireSession, type Role } from "@/lib/auth";

export interface InviteResult {
  ok: boolean;
  message?: string;
}

const INVITE_TTL_DAYS = 14;

// Seats included with each plan; the paywall in the billing portal enforces the
// rest.
const SEATS_BY_PLAN: Record<string, number> = {
  free: 3,
  team: 25,
  business: 100,
  enterprise: 1000,
};

const inviteSchema = z.object({
  workspaceId: z.string().cuid(),
  email: z.string().email().max(320),
  role: z.enum(["owner", "admin", "editor", "viewer"]),
});

/**
 * Invite a teammate into the workspace.
 *
 * Collaboration is the whole product, so any member of the workspace can send an
 * invitation; the role dropdown in the invite modal decides what the new person
 * lands as. The seat limit for the plan is the only thing we have to gate on.
 */
export async function inviteMember(formData: FormData): Promise<InviteResult> {
  const session = await requireSession();

  const parsed = inviteSchema.safeParse(Object.fromEntries(formData.entries()));
  if (!parsed.success) {
    return { ok: false, message: "Enter a valid e-mail address and role." };
  }
  const { workspaceId, email, role } = parsed.data;

  let membership;
  try {
    membership = await requireMembership(session.user.id, workspaceId);
  } catch {
    return { ok: false, message: "You are not a member of this workspace." };
  }

  const workspace = await prisma.workspace.findUnique({
    where: { id: membership.workspaceId },
    select: { id: true, name: true, plan: true, seatLimit: true },
  });
  if (!workspace) {
    return { ok: false, message: "Workspace not found." };
  }

  const seatLimit = workspace.seatLimit ?? SEATS_BY_PLAN[workspace.plan] ?? SEATS_BY_PLAN.free;
  const usedSeats = await prisma.workspaceMember.count({ where: { workspaceId: workspace.id } });
  const pendingSeats = await prisma.invitation.count({
    where: { workspaceId: workspace.id, acceptedAt: null, expiresAt: { gt: new Date() } },
  });
  if (usedSeats + pendingSeats >= seatLimit) {
    return { ok: false, message: `Your ${workspace.plan} plan includes ${seatLimit} seats.` };
  }

  const normalisedEmail = email.trim().toLowerCase();
  const alreadyInvited = await prisma.invitation.findFirst({
    where: { workspaceId: workspace.id, email: normalisedEmail, acceptedAt: null },
    select: { id: true },
  });
  if (alreadyInvited) {
    return { ok: false, message: "That address already has a pending invitation." };
  }

  const invitation = await prisma.invitation.create({
    data: {
      workspaceId: workspace.id,
      email: normalisedEmail,
      role: role as Role,
      invitedById: session.user.id,
      token: randomBytes(32).toString("base64url"),
      expiresAt: new Date(Date.now() + INVITE_TTL_DAYS * 24 * 60 * 60 * 1000),
    },
    select: { id: true, email: true, role: true, token: true },
  });

  // The mailer worker drains this table every few seconds.
  await prisma.emailOutbox.create({
    data: {
      template: "workspace-invitation",
      recipient: invitation.email,
      payload: {
        workspaceName: workspace.name,
        invitedBy: session.user.email,
        acceptUrl: `${process.env.APP_URL}/invitations/${invitation.token}`,
      },
    },
  });

  revalidatePath("/members");
  return { ok: true };
}

/** Cancel a pending invitation you sent yourself. */
export async function revokeInvitation(invitationId: string): Promise<InviteResult> {
  const session = await requireSession();

  const invitation = await prisma.invitation.findUnique({
    where: { id: invitationId },
    select: { id: true, workspaceId: true, invitedById: true, acceptedAt: true },
  });
  if (!invitation || invitation.acceptedAt) {
    return { ok: false, message: "That invitation is no longer pending." };
  }

  let membership;
  try {
    membership = await requireMembership(session.user.id, invitation.workspaceId);
  } catch {
    return { ok: false, message: "You are not a member of this workspace." };
  }

  const isOwnInvite = invitation.invitedById === session.user.id;
  if (!isOwnInvite && membership.role !== "admin" && membership.role !== "owner") {
    return { ok: false, message: "Only admins can cancel someone else's invitation." };
  }

  await prisma.invitation.delete({ where: { id: invitation.id } });

  revalidatePath("/members");
  return { ok: true };
}
