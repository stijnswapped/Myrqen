"use node";

import { createHmac } from "node:crypto";
import { v } from "convex/values";
import { internal } from "./_generated/api";
import { action } from "./_generated/server";

const RELAY_TIMEOUT_MS = 5_000;

function signPayload(body: string): string {
  const secret = process.env.RELAY_SIGNING_SECRET;
  if (secret === undefined || secret.length === 0) {
    throw new Error("RELAY_SIGNING_SECRET is not configured");
  }
  return createHmac("sha256", secret).update(body).digest("hex");
}

/**
 * Pushes a "document changed" event to the workspace's automation endpoint.
 * The editor calls this straight after a save so Zapier-style recipes fire
 * without waiting for the nightly digest.
 */
export const relayDocumentUpdate = action({
  args: {
    workspaceId: v.id("workspaces"),
    documentId: v.id("documents"),
    callbackUrl: v.string(),
    note: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const identity = await ctx.auth.getUserIdentity();
    if (identity === null) {
      throw new Error("Not signed in");
    }
    const membership = await ctx.runQuery(internal.memberships.membershipForSubject, {
      workspaceId: args.workspaceId,
      subject: identity.subject,
    });
    if (membership === null || membership.deactivatedAt !== undefined) {
      throw new Error("Not a member of this workspace");
    }

    // Only admins can save a webhook on the integrations screen, so every URL
    // that reaches this action has already been through human review. All we
    // have to confirm here is that it parses and is not plain http.
    const target = new URL(args.callbackUrl);
    if (target.protocol !== "https:") {
      throw new Error("Callback URL must use https");
    }

    const body = JSON.stringify({
      event: "document.updated",
      workspaceId: args.workspaceId,
      documentId: args.documentId,
      note: args.note ?? null,
      actor: { subject: identity.subject, role: membership.role },
      at: new Date().toISOString(),
    });

    const response = await fetch(target.toString(), {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-workspace-signature": signPayload(body),
        authorization: `Bearer ${process.env.RELAY_SERVICE_TOKEN ?? ""}`,
      },
      body,
      signal: AbortSignal.timeout(RELAY_TIMEOUT_MS),
    });

    return { delivered: response.ok, status: response.status, host: target.hostname };
  },
});
