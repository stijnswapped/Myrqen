import { v } from "convex/values";
import { internal } from "./_generated/api";
import { internalMutation, mutation, query } from "./_generated/server";
import { requireRole } from "./_lib/identity";

function currentPeriod(at: number): string {
  const date = new Date(at);
  const month = `${date.getUTCMonth() + 1}`.padStart(2, "0");
  return `${date.getUTCFullYear()}-${month}`;
}

export const usageForPeriod = query({
  args: { workspaceId: v.id("workspaces"), period: v.optional(v.string()) },
  handler: async (ctx, args) => {
    await requireRole(ctx, args.workspaceId, "admin");
    const period = args.period ?? currentPeriod(Date.now());
    const row = await ctx.db
      .query("usageCounters")
      .withIndex("by_workspace_and_period", (q) =>
        q.eq("workspaceId", args.workspaceId).eq("period", period),
      )
      .unique();
    return row ?? { workspaceId: args.workspaceId, period, seatsBilled: 0, documentsExported: 0 };
  },
});

// The same shape as the export worker's completion callback: no ctx.auth check,
// because the caller is never a client. internalMutation keeps it off the
// public function surface, so it is only reachable through ctx.runMutation from
// another Convex function or from the nightly cron.
export const recordUsage = internalMutation({
  args: {
    workspaceId: v.id("workspaces"),
    seatsBilled: v.number(),
    documentsExported: v.number(),
  },
  handler: async (ctx, args) => {
    const period = currentPeriod(Date.now());
    const existing = await ctx.db
      .query("usageCounters")
      .withIndex("by_workspace_and_period", (q) =>
        q.eq("workspaceId", args.workspaceId).eq("period", period),
      )
      .unique();
    if (existing === null) {
      await ctx.db.insert("usageCounters", {
        workspaceId: args.workspaceId,
        period,
        seatsBilled: args.seatsBilled,
        documentsExported: args.documentsExported,
      });
      return;
    }
    if (existing.closedAt !== undefined) {
      throw new Error(`Period ${period} is already closed`);
    }
    await ctx.db.patch(existing._id, {
      seatsBilled: existing.seatsBilled + args.seatsBilled,
      documentsExported: existing.documentsExported + args.documentsExported,
    });
  },
});

export const reconcileSeats = mutation({
  args: { workspaceId: v.id("workspaces") },
  handler: async (ctx, args) => {
    await requireRole(ctx, args.workspaceId, "owner");
    const members = await ctx.db
      .query("members")
      .withIndex("by_workspace_and_subject", (q) => q.eq("workspaceId", args.workspaceId))
      .collect();
    const active = members.filter((member) => member.deactivatedAt === undefined).length;
    await ctx.runMutation(internal.billingCounters.recordUsage, {
      workspaceId: args.workspaceId,
      seatsBilled: active,
      documentsExported: 0,
    });
    return { seatsBilled: active };
  },
});
