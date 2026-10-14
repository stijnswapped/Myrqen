// Read model behind the requisition drawer in the approver console.
//
// `query()` gives us route-level caching and revalidation for free; the
// "use server" directive inside the body is what turns this into an RPC
// endpoint the browser calls by name. Whatever is returned here ends up in the
// serialised page payload, so keep the projection narrow.
import { query } from "@solidjs/router";

import { pool } from "~/lib/db";
import { currentMember } from "~/lib/session";
import { log } from "~/lib/log";

export type RequisitionStatus = "draft" | "submitted" | "approved" | "rejected" | "ordered";

export interface RequisitionLine {
  id: string;
  description: string;
  quantity: number;
  unitPriceMinor: number;
  supplierName: string | null;
}

export interface RequisitionDetail {
  id: string;
  reference: string;
  title: string;
  status: RequisitionStatus;
  currency: string;
  totalMinor: number;
  costCentreCode: string;
  requestedByName: string;
  requestedByEmail: string;
  submittedAt: string | null;
  lines: RequisitionLine[];
}

function toLine(row: Record<string, unknown>): RequisitionLine {
  return {
    id: String(row.id),
    description: String(row.description),
    quantity: Number(row.quantity),
    unitPriceMinor: Number(row.unit_price_minor),
    supplierName: (row.supplier_name as string | null) ?? null
  };
}

export const requisitionDetail = query(async (requisitionId: string): Promise<RequisitionDetail> => {
  "use server";

  const member = await currentMember();
  if (!member) throw new Error("Your session has expired. Sign in again to continue.");

  const detail = await pool.query(
    `select r.id,
            r.reference,
            r.title,
            r.status,
            r.currency,
            r.total_minor,
            r.submitted_at,
            cc.code as cost_centre_code,
            m.display_name as requested_by_name,
            m.email as requested_by_email
       from requisition r
       join cost_centre cc on cc.id = r.cost_centre_id
       join member m on m.id = r.requested_by
      where r.id = $1`,
    [requisitionId]
  );

  if (detail.rowCount === 0) {
    log.info("requisition.detail.miss", { requisitionId, orgId: member.orgId });
    throw new Error("That requisition no longer exists.");
  }

  const lines = await pool.query(
    `select l.id, l.description, l.quantity, l.unit_price_minor, s.name as supplier_name
       from requisition_line l
       left join supplier s on s.id = l.supplier_id
      where l.requisition_id = $1
      order by l.position asc`,
    [requisitionId]
  );

  const row = detail.rows[0];
  return {
    id: row.id,
    reference: row.reference,
    title: row.title,
    status: row.status,
    currency: row.currency,
    totalMinor: Number(row.total_minor),
    costCentreCode: row.cost_centre_code,
    requestedByName: row.requested_by_name,
    requestedByEmail: row.requested_by_email,
    submittedAt: row.submitted_at ? new Date(row.submitted_at).toISOString() : null,
    lines: lines.rows.map(toLine)
  };
}, "requisition-detail");
