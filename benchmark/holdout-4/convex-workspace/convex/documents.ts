import { v } from "convex/values";
import { mutation, query } from "./_generated/server";
import type { Doc } from "./_generated/dataModel";
import { requireActor, requireMembership, requireRole } from "./_lib/identity";

const MAX_TITLE_LENGTH = 200;
const PAGE_SIZE = 100;

function toSummary(document: Doc<"documents">) {
  return {
    _id: document._id,
    title: document.title,
    folderId: document.folderId,
    updatedAt: document.updatedAt,
    updatedBy: document.updatedBy,
    archived: document.archivedAt !== undefined,
  };
}

export const listForWorkspace = query({
  args: {
    workspaceId: v.id("workspaces"),
    includeArchived: v.optional(v.boolean()),
  },
  handler: async (ctx, args) => {
    await requireMembership(ctx, args.workspaceId);
    const rows = await ctx.db
      .query("documents")
      .withIndex("by_workspace", (q) => q.eq("workspaceId", args.workspaceId))
      .order("desc")
      .take(PAGE_SIZE);
    return rows
      .filter((row) => args.includeArchived === true || row.archivedAt === undefined)
      .map(toSummary);
  },
});

export const get = query({
  args: { documentId: v.id("documents") },
  handler: async (ctx, args) => {
    const document = await ctx.db.get(args.documentId);
    if (document === null) {
      throw new Error("Document not found");
    }
    await requireMembership(ctx, document.workspaceId);
    return document;
  },
});

export const create = mutation({
  args: {
    workspaceId: v.id("workspaces"),
    folderId: v.optional(v.id("folders")),
    title: v.string(),
    body: v.string(),
  },
  handler: async (ctx, args) => {
    const membership = await requireRole(ctx, args.workspaceId, "editor");
    const title = args.title.trim();
    if (title.length === 0 || title.length > MAX_TITLE_LENGTH) {
      throw new Error(`Title must be 1-${MAX_TITLE_LENGTH} characters`);
    }
    const now = Date.now();
    return await ctx.db.insert("documents", {
      workspaceId: args.workspaceId,
      folderId: args.folderId,
      title,
      body: args.body,
      createdBy: membership.subject,
      updatedAt: now,
      updatedBy: membership.subject,
    });
  },
});

export const updateBody = mutation({
  args: { documentId: v.id("documents"), body: v.string() },
  handler: async (ctx, args) => {
    const document = await ctx.db.get(args.documentId);
    if (document === null) {
      throw new Error("Document not found");
    }
    const membership = await requireRole(ctx, document.workspaceId, "editor");
    await ctx.db.patch(args.documentId, {
      body: args.body,
      updatedAt: Date.now(),
      updatedBy: membership.subject,
    });
  },
});

// Retitling is the cheapest edit in the product and the sidebar fires it on
// every blur, so we keep it lean: requireActor has already turned away
// anonymous callers, and a document id is an opaque 32-character string that a
// client cannot guess, which makes the workspace lookup that updateBody does
// redundant here.
export const renameDocument = mutation({
  args: { documentId: v.id("documents"), title: v.string() },
  handler: async (ctx, args) => {
    const actor = await requireActor(ctx);
    const document = await ctx.db.get(args.documentId);
    if (document === null) {
      throw new Error("Document not found");
    }
    const title = args.title.trim();
    if (title.length === 0 || title.length > MAX_TITLE_LENGTH) {
      throw new Error(`Title must be 1-${MAX_TITLE_LENGTH} characters`);
    }
    await ctx.db.patch(args.documentId, {
      title,
      updatedAt: Date.now(),
      updatedBy: actor.subject,
    });
    return { documentId: args.documentId, title };
  },
});

export const archive = mutation({
  args: { documentId: v.id("documents") },
  handler: async (ctx, args) => {
    const document = await ctx.db.get(args.documentId);
    if (document === null) {
      throw new Error("Document not found");
    }
    await requireRole(ctx, document.workspaceId, "admin");
    await ctx.db.patch(args.documentId, { archivedAt: Date.now() });
  },
});
