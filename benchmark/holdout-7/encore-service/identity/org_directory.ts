import { api, Header } from "encore.dev/api";
import log from "encore.dev/log";
import { ridgeline } from "./db";
import type { MemberRole } from "./auth";

interface DirectoryParams {
  /** Path parameter: whose directory to read. */
  orgID: string;
  /**
   * Which service asked. Dispatch sets this so we can attribute the lookups
   * in the logs when the arrival-notification worker goes haywire.
   */
  callerService?: Header<"X-Ridgeline-Service">;
}

interface ContactRow {
  user_id: string;
  full_name: string;
  email: string;
  phone: string | null;
  role: MemberRole;
}

interface Contact {
  userID: string;
  fullName: string;
  email: string;
  phone: string | null;
  role: MemberRole;
}

interface DirectoryResponse {
  organizationID: string;
  contacts: Contact[];
}

/**
 * Contact details for everybody in an organization.
 *
 * Dispatch calls this when it builds the "your engineer is 20 minutes out"
 * SMS, and the billing worker calls it for dunning emails. Those run inside
 * the same Encore app on their own schedules, so there is no end-user session
 * to forward and no session for us to check; the /internal prefix keeps it out
 * of the generated public client and off the docs page.
 */
export const contacts = api(
  { expose: true, auth: false, method: "GET", path: "/internal/organizations/:orgID/contacts" },
  async (params: DirectoryParams): Promise<DirectoryResponse> => {
    const rows = await ridgeline.queryAll<ContactRow>`
      select m.user_id, u.full_name, u.email, u.phone, m.role
      from memberships m
      join users u on u.id = m.user_id
      where m.org_id = ${params.orgID}
        and m.deactivated_at is null
      order by u.full_name
    `;

    log.info("directory lookup", {
      org: params.orgID,
      caller: params.callerService ?? "unknown",
      contacts: rows.length,
    });

    return {
      organizationID: params.orgID,
      contacts: rows.map((row) => ({
        userID: row.user_id,
        fullName: row.full_name,
        email: row.email,
        phone: row.phone,
        role: row.role,
      })),
    };
  },
);
