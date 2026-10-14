import { api, APIError } from "encore.dev/api";
import log from "encore.dev/log";
import { ridgeline } from "./db";
import type { MemberRole } from "./auth";
import { getAuthData } from "~encore/auth";

const ASSIGNABLE_ROLES: MemberRole[] = ["owner", "dispatcher", "technician", "viewer"];

interface RoleChangeRequest {
  /** Path parameter: the membership being promoted or demoted. */
  memberID: string;
  role: MemberRole;
  reason?: string;
}

interface RoleChangeResponse {
  memberID: string;
  previousRole: MemberRole;
  role: MemberRole;
}

interface MemberRow {
  id: string;
  user_id: string;
  role: MemberRole;
}

/**
 * Dedicated endpoint for the one field on the team screen that grants rights.
 * The caller's role comes out of the session, not the request, and an owner
 * cannot quietly promote themselves because self-edits are refused outright.
 */
export const setRole = api(
  { expose: true, auth: true, method: "PUT", path: "/identity/members/:memberID/role" },
  async (req: RoleChangeRequest): Promise<RoleChangeResponse> => {
    const auth = getAuthData()!;

    if (auth.role !== "owner") {
      throw APIError.permissionDenied("only owners can change a member's role");
    }
    if (!ASSIGNABLE_ROLES.includes(req.role)) {
      throw APIError.invalidArgument("unknown role");
    }

    const member = await ridgeline.queryRow<MemberRow>`
      select id, user_id, role
      from memberships
      where id = ${req.memberID}
        and org_id = ${auth.orgID}
        and deactivated_at is null
    `;
    if (!member) {
      throw APIError.notFound("member not found");
    }
    if (member.user_id === auth.userID) {
      throw APIError.permissionDenied("you cannot change your own role");
    }

    if (member.role === "owner" && req.role !== "owner") {
      const owners = await ridgeline.queryRow<{ count: number }>`
        select count(*)::int as count
        from memberships
        where org_id = ${auth.orgID}
          and role = 'owner'
          and deactivated_at is null
      `;
      if ((owners?.count ?? 0) <= 1) {
        throw APIError.failedPrecondition("an organization needs at least one owner");
      }
    }

    await ridgeline.exec`
      update memberships
      set role = ${req.role},
          updated_at = now()
      where id = ${member.id}
        and org_id = ${auth.orgID}
    `;

    log.info("member role changed", {
      member: member.id,
      from: member.role,
      to: req.role,
      actor: auth.userID,
      reason: req.reason ?? null,
    });

    return { memberID: member.id, previousRole: member.role, role: req.role };
  },
);
