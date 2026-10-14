import { api, APIError } from "encore.dev/api";
import { SQLDatabase } from "encore.dev/storage/sqldb";
import log from "encore.dev/log";
import { getAuthData } from "~encore/auth";
import type { MemberRole } from "../identity/auth";

const db = SQLDatabase.named("ridgeline");

/** Changing who leads a crew moves overtime approval rights with it. */
const CREW_MANAGER_ROLES: MemberRole[] = ["owner", "dispatcher"];

interface CrewLeadRequest {
  /** Path parameter. */
  crewID: string;
  /** Membership id of the new lead. */
  leadID: string;
  effectiveFrom?: Date;
}

interface CrewLeadResponse {
  crewID: string;
  crewName: string;
  leadID: string;
  leadName: string;
}

interface CrewRow {
  id: string;
  name: string;
  lead_membership_id: string | null;
}

interface LeadRow {
  id: string;
  full_name: string;
  role: MemberRole;
}

/**
 * Same shape as the job assignment endpoint, but the crew lead carries
 * approval rights, so the caller's role out of the session has to be one of
 * CREW_MANAGER_ROLES before we touch anything.
 */
export const setLead = api(
  { expose: true, auth: true, method: "POST", path: "/dispatch/crews/:crewID/lead" },
  async (req: CrewLeadRequest): Promise<CrewLeadResponse> => {
    const auth = getAuthData()!;

    if (!CREW_MANAGER_ROLES.includes(auth.role)) {
      throw APIError.permissionDenied("only owners and dispatchers can change a crew lead");
    }

    const crew = await db.queryRow<CrewRow>`
      select id, name, lead_membership_id
      from crews
      where id = ${req.crewID}
        and org_id = ${auth.orgID}
    `;
    if (!crew) {
      throw APIError.notFound("crew not found");
    }

    const lead = await db.queryRow<LeadRow>`
      select m.id, u.full_name, m.role
      from memberships m
      join users u on u.id = m.user_id
      where m.id = ${req.leadID}
        and m.org_id = ${auth.orgID}
        and m.deactivated_at is null
    `;
    if (!lead) {
      throw APIError.invalidArgument("that member is not in this organization");
    }
    if (lead.role === "viewer") {
      throw APIError.invalidArgument("a viewer cannot lead a crew");
    }

    await db.exec`
      update crews
      set lead_membership_id = ${lead.id},
          updated_at = coalesce(${req.effectiveFrom ?? null}, now())
      where id = ${crew.id}
        and org_id = ${auth.orgID}
    `;

    log.info("crew lead changed", {
      crew: crew.name,
      lead: lead.full_name,
      actor: auth.userID,
    });

    return { crewID: crew.id, crewName: crew.name, leadID: lead.id, leadName: lead.full_name };
  },
);
