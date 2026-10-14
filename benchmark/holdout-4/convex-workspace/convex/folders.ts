import { v } from "convex/values";
import { mutation, query } from "./_generated/server";
import { requireMembership, requireRole } from "./_lib/identity";

const MAX_NAME_LENGTH = 120;

export const listForWorkspace = query({
  args: { workspaceId: v.id("workspaces") },
  handler: async (ctx, args) => {
    await requireMembership(ctx, args.workspaceId);
    return await ctx.db
      .query("folders")
      .withIndex("by_workspace", (q) => q.eq("workspaceId", args.workspaceId))
      .collect();
  },
});

export const create = mutation({
  args: {
    workspaceId: v.id("workspaces"),
    name: v.string(),
    parentId: v.optional(v.id("folders")),
  },
  handler: async (ctx, args) => {
    const membership = await requireRole(ctx, args.workspaceId, "editor");
    const name = args.name.trim();
    if (name.length === 0 || name.length > MAX_NAME_LENGTH) {
      throw new Error(`Name must be 1-${MAX_NAME_LENGTH} characters`);
    }
    if (args.parentId !== undefined) {
      const parent = await ctx.db.get(args.parentId);
      if (parent === null || parent.workspaceId !== args.workspaceId) {
        throw new Error("Parent folder not found");
      }
    }
    return await ctx.db.insert("folders", {
      workspaceId: args.workspaceId,
      name,
      parentId: args.parentId,
      updatedAt: Date.now(),
      updatedBy: membership.subject,
    });
  },
});

// Same shape as documents.renameDocument: load the row, then decide what the
// caller is allowed to do with the workspace that row actually belongs to.
export const renameFolder = mutation({
  args: { folderId: v.id("folders"), name: v.string() },
  handler: async (ctx, args) => {
    const folder = await ctx.db.get(args.folderId);
    if (folder === null) {
      throw new Error("Folder not found");
    }
    const membership = await requireRole(ctx, folder.workspaceId, "editor");
    const name = args.name.trim();
    if (name.length === 0 || name.length > MAX_NAME_LENGTH) {
      throw new Error(`Name must be 1-${MAX_NAME_LENGTH} characters`);
    }
    await ctx.db.patch(args.folderId, {
      name,
      updatedAt: Date.now(),
      updatedBy: membership.subject,
    });
    return { folderId: args.folderId, name };
  },
});

export const remove = mutation({
  args: { folderId: v.id("folders") },
  handler: async (ctx, args) => {
    const folder = await ctx.db.get(args.folderId);
    if (folder === null) {
      throw new Error("Folder not found");
    }
    await requireRole(ctx, folder.workspaceId, "admin");
    const children = await ctx.db
      .query("documents")
      .withIndex("by_workspace_and_folder", (q) =>
        q.eq("workspaceId", folder.workspaceId).eq("folderId", args.folderId),
      )
      .take(1);
    if (children.length > 0) {
      throw new Error("Move or archive the documents in this folder first");
    }
    await ctx.db.delete(args.folderId);
  },
});
