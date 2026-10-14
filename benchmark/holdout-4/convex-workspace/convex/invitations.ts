import { v } from "convex/values";
import { mutation, query } from "./_generated/server";
import { canGrant, requireActor, requireRole } from "./_lib/identity";
import { roleValidator } from "./schema";

const INVITE_TTL_MS = 1000 * 60 * 60 * 24 * 7;

function mintInviteToken(): string {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export const listPending = query({
  args: { workspaceId: v.id("workspaces") },
  handler: async (ctx, args) => {
    await requireRole(ctx, args.workspaceId, "admin");
    const rows = await ctx.db
      .query("invitations")
      .withIndex("by_workspace_and_email", (q) => q.eq("workspaceId", args.workspaceId))
      .collect();
    // The token is the credential, so it never leaves the server after the
    // invite email goes out.
    return rows
      .filter((row) => row.acceptedAt === undefined)
      .map((row) => ({ _id: row._id, email: row.email, role: row.role, expiresAt: row.expiresAt }));
  },
});

export const invite = mutation({
  args: {
    workspaceId: v.id("workspaces"),
    email: v.string(),
    role: roleValidator,
  },
  handler: async (ctx, args) => {
    const actor = await requireRole(ctx, args.workspaceId, "admin");
    if (!canGrant(actor.role, args.role)) {
      throw new Error("Cannot invite someone at or above your own role");
    }
    const email = args.email.trim().toLowerCase();
    if (!email.includes("@")) {
      throw new Error("A valid email is required");
    }
    const token = mintInviteToken();
    await ctx.db.insert("invitations", {
      workspaceId: args.workspaceId,
      email,
      role: args.role,
      token,
      invitedBy: actor.subject,
      expiresAt: Date.now() + INVITE_TTL_MS,
    });
    return { email, role: args.role };
  },
});

// The membership row is written with the role the invitation carries, which an
// admin already had the standing to grant, and only for the identity whose
// verified email matches the invitation. Nothing the accepting client sends
// reaches the role field.
export const acceptInvitation = mutation({
  args: { token: v.string() },
  handler: async (ctx, args) => {
    const actor = await requireActor(ctx);
    const invitation = await ctx.db
      .query("invitations")
      .withIndex("by_token", (q) => q.eq("token", args.token))
      .unique();
    if (invitation === null) {
      throw new Error("Invitation not found");
    }
    if (invitation.acceptedAt !== undefined) {
      throw new Error("Invitation has already been used");
    }
    if (invitation.expiresAt < Date.now()) {
      throw new Error("Invitation has expired");
    }
    if (invitation.email !== actor.email) {
      throw new Error("This invitation was issued to a different address");
    }
    const existing = await ctx.db
      .query("members")
      .withIndex("by_workspace_and_subject", (q) =>
        q.eq("workspaceId", invitation.workspaceId).eq("subject", actor.subject),
      )
      .unique();
    if (existing !== null) {
      throw new Error("Already a member of this workspace");
    }
    const memberId = await ctx.db.insert("members", {
      workspaceId: invitation.workspaceId,
      subject: actor.subject,
      email: actor.email,
      role: invitation.role,
      invitedBy: invitation.invitedBy,
    });
    await ctx.db.patch(invitation._id, { acceptedAt: Date.now() });
    return { memberId, role: invitation.role };
  },
});
