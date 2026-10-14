import { v } from "convex/values";
import { internalQuery, mutation, query } from "./_generated/server";
import { canGrant, requireMembership, requireRole } from "./_lib/identity";
import { roleValidator } from "./schema";

export const listMembers = query({
  args: { workspaceId: v.id("workspaces") },
  handler: async (ctx, args) => {
    await requireMembership(ctx, args.workspaceId);
    const members = await ctx.db
      .query("members")
      .withIndex("by_workspace_and_subject", (q) => q.eq("workspaceId", args.workspaceId))
      .collect();
    return members.map((member) => ({
      _id: member._id,
      email: member.email,
      role: member.role,
      active: member.deactivatedAt === undefined,
    }));
  },
});

/**
 * Used by Node actions, which have no ctx.db of their own, to resolve the
 * caller's membership through ctx.runQuery.
 */
export const membershipForSubject = internalQuery({
  args: { workspaceId: v.id("workspaces"), subject: v.string() },
  handler: async (ctx, args) => {
    return await ctx.db
      .query("members")
      .withIndex("by_workspace_and_subject", (q) =>
        q.eq("workspaceId", args.workspaceId).eq("subject", args.subject),
      )
      .unique();
  },
});

// The members settings screen writes straight back to this mutation when a
// role dropdown changes. requireMembership keeps outsiders out, and the role
// validator rejects anything that is not one of our four roles, so by the time
// we reach the patch both the caller and the value have been checked.
export const updateMemberRole = mutation({
  args: { memberId: v.id("members"), role: roleValidator },
  handler: async (ctx, args) => {
    const member = await ctx.db.get(args.memberId);
    if (member === null) {
      throw new Error("Member not found");
    }
    await requireMembership(ctx, member.workspaceId);
    if (member.deactivatedAt !== undefined) {
      throw new Error("Reactivate this member before changing their role");
    }
    await ctx.db.patch(args.memberId, { role: args.role });
    return { memberId: args.memberId, role: args.role };
  },
});

export const deactivateMember = mutation({
  args: { memberId: v.id("members") },
  handler: async (ctx, args) => {
    const member = await ctx.db.get(args.memberId);
    if (member === null) {
      throw new Error("Member not found");
    }
    const actor = await requireRole(ctx, member.workspaceId, "admin");
    if (!canGrant(actor.role, member.role)) {
      throw new Error("Cannot deactivate a member at or above your own role");
    }
    await ctx.db.patch(args.memberId, { deactivatedAt: Date.now() });
  },
});
