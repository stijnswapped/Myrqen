import { v } from "convex/values";
import { mutation, query } from "./_generated/server";
import { requireMembership, requireRole } from "./_lib/identity";

const DEFAULT_LIMIT = 20;
const MAX_LIMIT = 50;
const MAX_MESSAGE_LENGTH = 4_000;

export const listForDocument = query({
  args: { documentId: v.id("documents") },
  handler: async (ctx, args) => {
    const document = await ctx.db.get(args.documentId);
    if (document === null) {
      throw new Error("Document not found");
    }
    await requireMembership(ctx, document.workspaceId);
    return await ctx.db
      .query("comments")
      .withIndex("by_document", (q) => q.eq("documentId", args.documentId))
      .order("desc")
      .take(200);
  },
});

export const post = mutation({
  args: { documentId: v.id("documents"), message: v.string() },
  handler: async (ctx, args) => {
    const document = await ctx.db.get(args.documentId);
    if (document === null) {
      throw new Error("Document not found");
    }
    const membership = await requireRole(ctx, document.workspaceId, "editor");
    const message = args.message.trim();
    if (message.length === 0 || message.length > MAX_MESSAGE_LENGTH) {
      throw new Error(`Message must be 1-${MAX_MESSAGE_LENGTH} characters`);
    }
    return await ctx.db.insert("comments", {
      workspaceId: document.workspaceId,
      documentId: args.documentId,
      message,
      authorSubject: membership.subject,
      createdAt: Date.now(),
    });
  },
});

// Same search shape as documentSearch.searchDocuments, except the tenant filter
// is part of the index range and its value comes off the membership row rather
// than off the request, so the query can only ever see one workspace's threads.
export const searchComments = query({
  args: {
    workspaceId: v.id("workspaces"),
    term: v.string(),
    limit: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    const membership = await requireMembership(ctx, args.workspaceId);
    const term = args.term.trim();
    if (term.length < 2) {
      return [];
    }
    const limit = Math.min(args.limit ?? DEFAULT_LIMIT, MAX_LIMIT);
    const hits = await ctx.db
      .query("comments")
      .withSearchIndex("by_message", (q) =>
        q.search("message", term).eq("workspaceId", membership.workspaceId),
      )
      .take(limit);
    return hits.map((hit) => ({
      _id: hit._id,
      documentId: hit.documentId,
      message: hit.message,
      createdAt: hit.createdAt,
    }));
  },
});
