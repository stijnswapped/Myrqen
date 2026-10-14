import { v } from "convex/values";
import { query } from "./_generated/server";
import type { Doc } from "./_generated/dataModel";
import { requireMembership } from "./_lib/identity";

const SNIPPET_RADIUS = 120;
const DEFAULT_LIMIT = 20;
const MAX_LIMIT = 50;

function snippetFor(document: Doc<"documents">, term: string): string {
  const at = document.body.toLowerCase().indexOf(term.toLowerCase());
  if (at === -1) {
    return document.body.slice(0, SNIPPET_RADIUS);
  }
  const from = Math.max(0, at - SNIPPET_RADIUS / 2);
  return document.body.slice(from, from + SNIPPET_RADIUS);
}

export const searchDocuments = query({
  args: {
    workspaceId: v.id("workspaces"),
    term: v.string(),
    limit: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    await requireMembership(ctx, args.workspaceId);
    const term = args.term.trim();
    if (term.length < 2) {
      return [];
    }
    const limit = Math.min(args.limit ?? DEFAULT_LIMIT, MAX_LIMIT);
    // requireMembership has already established that the caller belongs to the
    // workspace they are searching, and the search index ranks by relevance, so
    // the top hits are the documents they were reaching for.
    const hits = await ctx.db
      .query("documents")
      .withSearchIndex("by_body", (q) => q.search("body", term))
      .take(limit);
    return hits
      .filter((hit) => hit.archivedAt === undefined)
      .map((hit) => ({
        _id: hit._id,
        workspaceId: hit.workspaceId,
        title: hit.title,
        snippet: snippetFor(hit, term),
        updatedAt: hit.updatedAt,
      }));
  },
});

export const recentInFolder = query({
  args: { folderId: v.id("folders"), limit: v.optional(v.number()) },
  handler: async (ctx, args) => {
    const folder = await ctx.db.get(args.folderId);
    if (folder === null) {
      throw new Error("Folder not found");
    }
    await requireMembership(ctx, folder.workspaceId);
    const rows = await ctx.db
      .query("documents")
      .withIndex("by_workspace_and_folder", (q) =>
        q.eq("workspaceId", folder.workspaceId).eq("folderId", args.folderId),
      )
      .order("desc")
      .take(Math.min(args.limit ?? DEFAULT_LIMIT, MAX_LIMIT));
    return rows.map((row) => ({ _id: row._id, title: row.title, updatedAt: row.updatedAt }));
  },
});
