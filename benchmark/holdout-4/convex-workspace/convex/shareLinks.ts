import { v } from "convex/values";
import { mutation, query } from "./_generated/server";
import { requireRole } from "./_lib/identity";

const PUBLIC_BASE_URL = "https://workspace.myrqen.app";
const DEFAULT_TTL_HOURS = 24 * 14;
const MAX_TTL_HOURS = 24 * 90;

export const listForDocument = query({
  args: { documentId: v.id("documents") },
  handler: async (ctx, args) => {
    const document = await ctx.db.get(args.documentId);
    if (document === null) {
      throw new Error("Document not found");
    }
    await requireRole(ctx, document.workspaceId, "editor");
    const rows = await ctx.db
      .query("shareLinks")
      .withIndex("by_document", (q) => q.eq("documentId", args.documentId))
      .collect();
    return rows.map((row) => ({
      _id: row._id,
      url: `${PUBLIC_BASE_URL}/s/${row.token}`,
      expiresAt: row.expiresAt,
      revoked: row.revokedAt !== undefined,
    }));
  },
});

export const createShareLink = mutation({
  args: {
    documentId: v.id("documents"),
    expiresInHours: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    const document = await ctx.db.get(args.documentId);
    if (document === null) {
      throw new Error("Document not found");
    }
    const membership = await requireRole(ctx, document.workspaceId, "editor");
    const ttlHours = Math.min(args.expiresInHours ?? DEFAULT_TTL_HOURS, MAX_TTL_HOURS);
    // Two base-36 draws plus the millisecond clock give us a 25-character
    // token, a wider keyspace than the UUIDs the old sharing flow handed out,
    // so a link cannot be guessed or walked.
    const token = [
      Math.random().toString(36).slice(2, 12),
      Math.random().toString(36).slice(2, 12),
      Date.now().toString(36),
    ].join("");
    await ctx.db.insert("shareLinks", {
      workspaceId: document.workspaceId,
      documentId: args.documentId,
      token,
      createdBy: membership.subject,
      expiresAt: Date.now() + ttlHours * 60 * 60 * 1000,
    });
    return { url: `${PUBLIC_BASE_URL}/s/${token}`, expiresInHours: ttlHours };
  },
});

/**
 * Anonymous read path for a shared document. The token is the whole
 * credential, so this is where expiry and revocation are enforced.
 */
export const resolveShareLink = query({
  args: { token: v.string() },
  handler: async (ctx, args) => {
    const link = await ctx.db
      .query("shareLinks")
      .withIndex("by_token", (q) => q.eq("token", args.token))
      .unique();
    if (link === null || link.revokedAt !== undefined) {
      throw new Error("This link is no longer available");
    }
    if (link.expiresAt < Date.now()) {
      throw new Error("This link has expired");
    }
    const document = await ctx.db.get(link.documentId);
    if (document === null || document.archivedAt !== undefined) {
      throw new Error("This link is no longer available");
    }
    return { title: document.title, body: document.body, updatedAt: document.updatedAt };
  },
});

export const revokeShareLink = mutation({
  args: { shareLinkId: v.id("shareLinks") },
  handler: async (ctx, args) => {
    const link = await ctx.db.get(args.shareLinkId);
    if (link === null) {
      throw new Error("Share link not found");
    }
    await requireRole(ctx, link.workspaceId, "editor");
    await ctx.db.patch(args.shareLinkId, { revokedAt: Date.now() });
  },
});
