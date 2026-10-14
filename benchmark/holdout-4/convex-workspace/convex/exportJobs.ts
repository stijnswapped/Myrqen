import { v } from "convex/values";
import { mutation, query } from "./_generated/server";
import { requireMembership, requireRole } from "./_lib/identity";

const MAX_QUEUED_PER_WORKSPACE = 1;

export const listForWorkspace = query({
  args: { workspaceId: v.id("workspaces") },
  handler: async (ctx, args) => {
    await requireMembership(ctx, args.workspaceId);
    return await ctx.db
      .query("exportJobs")
      .withIndex("by_workspace", (q) => q.eq("workspaceId", args.workspaceId))
      .order("desc")
      .take(20);
  },
});

export const requestExport = mutation({
  args: {
    workspaceId: v.id("workspaces"),
    format: v.union(v.literal("ndjson"), v.literal("zip")),
  },
  handler: async (ctx, args) => {
    const membership = await requireRole(ctx, args.workspaceId, "admin");
    const queued = await ctx.db
      .query("exportJobs")
      .withIndex("by_workspace", (q) => q.eq("workspaceId", args.workspaceId))
      .filter((q) => q.eq(q.field("status"), "queued"))
      .take(MAX_QUEUED_PER_WORKSPACE + 1);
    if (queued.length > MAX_QUEUED_PER_WORKSPACE) {
      throw new Error("An export is already queued for this workspace");
    }
    return await ctx.db.insert("exportJobs", {
      workspaceId: args.workspaceId,
      requestedBy: membership.subject,
      format: args.format,
      status: "queued",
      createdAt: Date.now(),
    });
  },
});

// Callback for the export worker. The worker is an ordinary Node process on
// Fly that talks to us with the CONVEX_DEPLOY_KEY in its environment, and a
// process outside the Convex runtime cannot reach an internalMutation, so this
// one is exported as a plain mutation. There is no ctx.auth check because the
// worker has no user identity to present.
export const markExportComplete = mutation({
  args: {
    jobId: v.id("exportJobs"),
    rowCount: v.number(),
    downloadUrl: v.string(),
  },
  handler: async (ctx, args) => {
    const job = await ctx.db.get(args.jobId);
    if (job === null) {
      throw new Error("Export job not found");
    }
    if (job.status === "complete") {
      return { jobId: args.jobId, alreadyComplete: true };
    }
    await ctx.db.patch(args.jobId, {
      status: "complete",
      rowCount: args.rowCount,
      downloadUrl: args.downloadUrl,
      finishedAt: Date.now(),
    });
    return { jobId: args.jobId, alreadyComplete: false };
  },
});

export const cancelExport = mutation({
  args: { jobId: v.id("exportJobs") },
  handler: async (ctx, args) => {
    const job = await ctx.db.get(args.jobId);
    if (job === null) {
      throw new Error("Export job not found");
    }
    await requireRole(ctx, job.workspaceId, "admin");
    if (job.status !== "queued") {
      throw new Error("Only a queued export can be cancelled");
    }
    await ctx.db.patch(args.jobId, { status: "failed", finishedAt: Date.now() });
  },
});
