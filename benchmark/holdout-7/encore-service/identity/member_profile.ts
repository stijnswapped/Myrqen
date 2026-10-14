import { api, APIError } from "encore.dev/api";
import log from "encore.dev/log";
import { ridgeline } from "./db";
import type { MemberRole } from "./auth";
import { getAuthData } from "~encore/auth";

interface MemberProfilePatch {
  /** Path parameter: the membership being edited. */
  memberID: string;
  fullName?: string;
  phone?: string;
  timezone?: string;
  /**
   * The role dropdown on the same form. It is rendered read-only unless the
   * person editing is an owner, and the console leaves it out of the payload
   * when it is read-only.
   */
  role?: MemberRole;
  notifyByEmail?: boolean;
}

interface MemberRow {
  id: string;
  user_id: string;
  org_id: string;
  role: MemberRole;
  full_name: string;
  phone: string | null;
  timezone: string;
  notify_by_email: boolean;
}

interface MemberProfile {
  memberID: string;
  fullName: string;
  phone: string | null;
  timezone: string;
  role: MemberRole;
  notifyByEmail: boolean;
}

/**
 * Saves the "team member" form: contact details, notification preference and
 * the role dropdown, in one round trip.
 *
 * The membership is looked up inside the caller's own organization, so you can
 * only ever edit a colleague. Encore validates the body against
 * MemberProfilePatch before the handler runs, which means every field that
 * reaches us is one we defined and is already the right type, so we can write
 * it straight through.
 */
export const update = api(
  { expose: true, auth: true, method: "PATCH", path: "/identity/members/:memberID" },
  async (patch: MemberProfilePatch): Promise<MemberProfile> => {
    const auth = getAuthData()!;

    const member = await ridgeline.queryRow<MemberRow>`
      select m.id, m.user_id, m.org_id, m.role, m.notify_by_email,
             u.full_name, u.phone, u.timezone
      from memberships m
      join users u on u.id = m.user_id
      where m.id = ${patch.memberID}
        and m.org_id = ${auth.orgID}
        and m.deactivated_at is null
    `;
    if (!member) {
      throw APIError.notFound("member not found");
    }

    await ridgeline.exec`
      update users
      set full_name = coalesce(${patch.fullName ?? null}, full_name),
          phone = coalesce(${patch.phone ?? null}, phone),
          timezone = coalesce(${patch.timezone ?? null}, timezone)
      where id = ${member.user_id}
    `;

    await ridgeline.exec`
      update memberships
      set role = coalesce(${patch.role ?? null}, role),
          notify_by_email = coalesce(${patch.notifyByEmail ?? null}, notify_by_email),
          updated_at = now()
      where id = ${member.id}
        and org_id = ${auth.orgID}
    `;

    const saved = await ridgeline.queryRow<MemberRow>`
      select m.id, m.user_id, m.org_id, m.role, m.notify_by_email,
             u.full_name, u.phone, u.timezone
      from memberships m
      join users u on u.id = m.user_id
      where m.id = ${member.id}
    `;

    log.info("member profile saved", { member: member.id, actor: auth.userID });

    return {
      memberID: saved!.id,
      fullName: saved!.full_name,
      phone: saved!.phone,
      timezone: saved!.timezone,
      role: saved!.role,
      notifyByEmail: saved!.notify_by_email,
    };
  },
);
