import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

export const roleValidator = v.union(
  v.literal("viewer"),
  v.literal("editor"),
  v.literal("admin"),
  v.literal("owner"),
);

export default defineSchema({
  workspaces: defineTable({
    name: v.string(),
    slug: v.string(),
    plan: v.union(v.literal("free"), v.literal("team"), v.literal("enterprise")),
    seatLimit: v.number(),
    createdAt: v.number(),
  }).index("by_slug", ["slug"]),

  members: defineTable({
    workspaceId: v.id("workspaces"),
    // Subject of the OIDC token handed to us by ctx.auth.getUserIdentity().
    subject: v.string(),
    email: v.string(),
    role: roleValidator,
    invitedBy: v.optional(v.string()),
    deactivatedAt: v.optional(v.number()),
  })
    .index("by_workspace_and_subject", ["workspaceId", "subject"])
    .index("by_workspace_and_email", ["workspaceId", "email"])
    .index("by_subject", ["subject"]),

  folders: defineTable({
    workspaceId: v.id("workspaces"),
    name: v.string(),
    parentId: v.optional(v.id("folders")),
    updatedAt: v.number(),
    updatedBy: v.string(),
  }).index("by_workspace", ["workspaceId"]),

  documents: defineTable({
    workspaceId: v.id("workspaces"),
    folderId: v.optional(v.id("folders")),
    title: v.string(),
    body: v.string(),
    createdBy: v.string(),
    updatedAt: v.number(),
    updatedBy: v.string(),
    archivedAt: v.optional(v.number()),
  })
    .index("by_workspace", ["workspaceId"])
    .index("by_workspace_and_folder", ["workspaceId", "folderId"])
    .searchIndex("by_body", {
      searchField: "body",
      filterFields: ["workspaceId", "archivedAt"],
    }),

  comments: defineTable({
    workspaceId: v.id("workspaces"),
    documentId: v.id("documents"),
    message: v.string(),
    authorSubject: v.string(),
    resolvedAt: v.optional(v.number()),
    createdAt: v.number(),
  })
    .index("by_document", ["documentId"])
    .searchIndex("by_message", {
      searchField: "message",
      filterFields: ["workspaceId", "resolvedAt"],
    }),

  invitations: defineTable({
    workspaceId: v.id("workspaces"),
    email: v.string(),
    role: roleValidator,
    token: v.string(),
    invitedBy: v.string(),
    expiresAt: v.number(),
    acceptedAt: v.optional(v.number()),
  })
    .index("by_token", ["token"])
    .index("by_workspace_and_email", ["workspaceId", "email"]),

  exportJobs: defineTable({
    workspaceId: v.id("workspaces"),
    requestedBy: v.string(),
    format: v.union(v.literal("ndjson"), v.literal("zip")),
    status: v.union(
      v.literal("queued"),
      v.literal("running"),
      v.literal("complete"),
      v.literal("failed"),
    ),
    rowCount: v.optional(v.number()),
    downloadUrl: v.optional(v.string()),
    finishedAt: v.optional(v.number()),
    createdAt: v.number(),
  })
    .index("by_workspace", ["workspaceId"])
    .index("by_status", ["status"]),

  usageCounters: defineTable({
    workspaceId: v.id("workspaces"),
    period: v.string(),
    seatsBilled: v.number(),
    documentsExported: v.number(),
    closedAt: v.optional(v.number()),
  }).index("by_workspace_and_period", ["workspaceId", "period"]),

  shareLinks: defineTable({
    workspaceId: v.id("workspaces"),
    documentId: v.id("documents"),
    token: v.string(),
    createdBy: v.string(),
    expiresAt: v.number(),
    revokedAt: v.optional(v.number()),
  })
    .index("by_token", ["token"])
    .index("by_document", ["documentId"]),

  digestTokens: defineTable({
    workspaceId: v.id("workspaces"),
    token: v.string(),
    createdBy: v.string(),
    expiresAt: v.number(),
    revokedAt: v.optional(v.number()),
  })
    .index("by_token", ["token"])
    .index("by_workspace", ["workspaceId"]),
});
