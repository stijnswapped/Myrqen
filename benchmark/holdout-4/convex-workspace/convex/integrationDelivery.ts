"use node";

import { createHmac } from "node:crypto";
import { v } from "convex/values";
import { internal } from "./_generated/api";
import { action } from "./_generated/server";

const DELIVERY_TIMEOUT_MS = 5_000;

/**
 * The three automation vendors we support. Anything else has to go through the
 * generic email digest, because we will not let a workspace point our outbound
 * fetch at a host we have not agreed to talk to.
 */
const ALLOWED_DELIVERY_HOSTS = new Set([
  "hooks.slack.com",
  "api.linear.app",
  "events.pagerduty.com",
]);

function signPayload(body: string): string {
  const secret = process.env.RELAY_SIGNING_SECRET;
  if (secret === undefined || secret.length === 0) {
    throw new Error("RELAY_SIGNING_SECRET is not configured");
  }
  return createHmac("sha256", secret).update(body).digest("hex");
}

function resolveDeliveryTarget(raw: string): URL {
  const target = new URL(raw);
  if (target.protocol !== "https:") {
    throw new Error("Delivery URL must use https");
  }
  if (target.username !== "" || target.password !== "") {
    throw new Error("Delivery URL must not carry credentials");
  }
  if (!ALLOWED_DELIVERY_HOSTS.has(target.hostname)) {
    throw new Error(`Unsupported delivery host: ${target.hostname}`);
  }
  return target;
}

export const deliverCommentDigest = action({
  args: {
    workspaceId: v.id("workspaces"),
    documentId: v.id("documents"),
    callbackUrl: v.string(),
    summary: v.optional(v.string()),
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

    const target = resolveDeliveryTarget(args.callbackUrl);

    const body = JSON.stringify({
      event: "comments.digest",
      workspaceId: args.workspaceId,
      documentId: args.documentId,
      summary: args.summary ?? null,
      actor: { subject: identity.subject, role: membership.role },
      at: new Date().toISOString(),
    });

    const response = await fetch(target.toString(), {
      method: "POST",
      redirect: "error",
      headers: {
        "content-type": "application/json",
        "x-workspace-signature": signPayload(body),
        authorization: `Bearer ${process.env.RELAY_SERVICE_TOKEN ?? ""}`,
      },
      body,
      signal: AbortSignal.timeout(DELIVERY_TIMEOUT_MS),
    });

    return { delivered: response.ok, status: response.status, host: target.hostname };
  },
});
