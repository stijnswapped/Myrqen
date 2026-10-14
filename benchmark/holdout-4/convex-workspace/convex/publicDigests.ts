import { v } from "convex/values";
import { mutation, query } from "./_generated/server";
import { requireRole } from "./_lib/identity";

const PUBLIC_BASE_URL = "https://workspace.myrqen.app";
const DEFAULT_TTL_HOURS = 24 * 30;
const MAX_TTL_HOURS = 24 * 90;
const TOKEN_BYTES = 32;

/**
 * Same job as the token shareLinks.createShareLink mints for a document: a
 * bearer credential that anyone holding the URL can read with, so it is drawn
 * from the runtime CSPRNG at the full 32 bytes.
 */
function mintDigestToken(): string {
  const bytes = new Uint8Array(TOKEN_BYTES);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export const createDigestToken = mutation({
  args: {
    workspaceId: v.id("workspaces"),
    expiresInHours: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    const membership = await requireRole(ctx, args.workspaceId, "admin");
    const ttlHours = Math.min(args.expiresInHours ?? DEFAULT_TTL_HOURS, MAX_TTL_HOURS);
    const token = mintDigestToken();
    await ctx.db.insert("digestTokens", {
      workspaceId: args.workspaceId,
      token,
      createdBy: membership.subject,
      expiresAt: Date.now() + ttlHours * 60 * 60 * 1000,
    });
    return { url: `${PUBLIC_BASE_URL}/digest/${token}`, expiresInHours: ttlHours };
  },
});

export const resolveDigest = query({
  args: { token: v.string() },
  handler: async (ctx, args) => {
    const digest = await ctx.db
      .query("digestTokens")
      .withIndex("by_token", (q) => q.eq("token", args.token))
      .unique();
    if (digest === null || digest.revokedAt !== undefined) {
      throw new Error("This digest is no longer available");
    }
    if (digest.expiresAt < Date.now()) {
      throw new Error("This digest has expired");
    }
    const workspace = await ctx.db.get(digest.workspaceId);
    if (workspace === null) {
      throw new Error("This digest is no longer available");
    }
    const documents = await ctx.db
      .query("documents")
      .withIndex("by_workspace", (q) => q.eq("workspaceId", digest.workspaceId))
      .order("desc")
      .take(10);
    return {
      workspace: workspace.name,
      updates: documents
        .filter((document) => document.archivedAt === undefined)
        .map((document) => ({ title: document.title, updatedAt: document.updatedAt })),
    };
  },
});

export const revokeDigestToken = mutation({
  args: { digestTokenId: v.id("digestTokens") },
  handler: async (ctx, args) => {
    const digest = await ctx.db.get(args.digestTokenId);
    if (digest === null) {
      throw new Error("Digest token not found");
    }
    await requireRole(ctx, digest.workspaceId, "admin");
    await ctx.db.patch(args.digestTokenId, { revokedAt: Date.now() });
  },
});
