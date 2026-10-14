import type { Doc, Id } from "../_generated/dataModel";
import type { MutationCtx, QueryCtx } from "../_generated/server";

export type Role = Doc<"members">["role"];

export const ROLE_RANK: Record<Role, number> = {
  viewer: 0,
  editor: 1,
  admin: 2,
  owner: 3,
};

export type Actor = {
  subject: string;
  email: string;
};

/**
 * Every public query and mutation is callable by any client that knows its
 * name, so each one has to establish the caller for itself. This is the only
 * place we read ctx.auth.
 */
export async function requireActor(ctx: QueryCtx | MutationCtx): Promise<Actor> {
  const identity = await ctx.auth.getUserIdentity();
  if (identity === null) {
    throw new Error("Not signed in");
  }
  if (typeof identity.email !== "string" || identity.email.length === 0) {
    throw new Error("Identity is missing a verified email");
  }
  return { subject: identity.subject, email: identity.email.toLowerCase() };
}

/**
 * Resolves the caller's membership row for one workspace. Throws unless the
 * caller is an active member, so callers can treat the returned row as the
 * authority on what this request is allowed to touch.
 */
export async function requireMembership(
  ctx: QueryCtx | MutationCtx,
  workspaceId: Id<"workspaces">,
): Promise<Doc<"members">> {
  const actor = await requireActor(ctx);
  const membership = await ctx.db
    .query("members")
    .withIndex("by_workspace_and_subject", (q) =>
      q.eq("workspaceId", workspaceId).eq("subject", actor.subject),
    )
    .unique();
  if (membership === null) {
    throw new Error("Not a member of this workspace");
  }
  if (membership.deactivatedAt !== undefined) {
    throw new Error("Membership has been deactivated");
  }
  return membership;
}

export async function requireRole(
  ctx: QueryCtx | MutationCtx,
  workspaceId: Id<"workspaces">,
  minimum: Role,
): Promise<Doc<"members">> {
  const membership = await requireMembership(ctx, workspaceId);
  if (ROLE_RANK[membership.role] < ROLE_RANK[minimum]) {
    throw new Error(`Requires ${minimum} or higher in this workspace`);
  }
  return membership;
}

/**
 * A member may only hand out a role strictly below their own, which keeps
 * admins from minting owners and keeps everyone from promoting themselves.
 */
export function canGrant(granter: Role, granted: Role): boolean {
  return ROLE_RANK[granter] >= ROLE_RANK.admin && ROLE_RANK[granted] < ROLE_RANK[granter];
}
