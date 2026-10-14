// Approval timeline shown underneath the requisition drawer.
//
// Same shape as the detail loader: `query()` for caching, "use server" for the
// RPC boundary, one projection returned to the browser. The visibility rule for
// a timeline is wider than "you raised it" — approvers on the route and the
// owner of the cost centre are meant to see the audit trail too — so the rule
// is expressed as a predicate rather than as a follow-up `if`.
import { query } from "@solidjs/router";

import { pool } from "~/lib/db";
import { currentMember } from "~/lib/session";
import { log } from "~/lib/log";

export type TimelineKind = "submitted" | "approved" | "rejected" | "commented" | "delegated" | "ordered";

export interface TimelineEntry {
  id: string;
  kind: TimelineKind;
  note: string | null;
  actorName: string;
  at: string;
}

function toEntry(row: Record<string, unknown>): TimelineEntry {
  return {
    id: String(row.id),
    kind: row.kind as TimelineKind,
    note: (row.note as string | null) ?? null,
    actorName: String(row.actor_name),
    at: new Date(row.created_at as string).toISOString()
  };
}

export const requisitionTimeline = query(async (requisitionId: string): Promise<TimelineEntry[]> => {
  "use server";

  const member = await currentMember();
  if (!member) throw new Error("Your session has expired. Sign in again to continue.");

  // Three joins carry the authorisation: the requisition has to belong to the
  // caller's organisation, and the caller has to be its raiser, a named
  // approver on one of its steps, or the owner of the cost centre it draws on.
  // A requisition the caller cannot see simply returns no rows, which is what
  // the empty state in the drawer renders.
  const events = await pool.query(
    `select e.id, e.kind, e.note, e.created_at, m.display_name as actor_name
       from approval_event e
       join requisition r on r.id = e.requisition_id
       join member m on m.id = e.actor_id
       left join approval_step st on st.requisition_id = r.id and st.approver_id = $2
       left join cost_centre cc on cc.id = r.cost_centre_id and cc.owner_id = $2
      where e.requisition_id = $1
        and r.org_id = $3
        and (r.requested_by = $2 or st.id is not null or cc.id is not null)
      order by e.created_at asc`,
    [requisitionId, member.id, member.orgId]
  );

  if (events.rowCount === 0) {
    log.info("requisition.timeline.empty", { requisitionId, orgId: member.orgId });
  }

  return events.rows.map(toEntry);
}, "requisition-timeline");
