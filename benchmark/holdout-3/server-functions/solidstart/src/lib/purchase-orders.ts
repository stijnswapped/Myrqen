// Issuing a purchase order from an approved requisition.
//
// `action()` posts the form back to this module over the server-function
// transport, so everything below the "use server" line runs on the box with the
// database connection. Buyers hit this from the approvals queue, and the queue
// is deliberately multi-user: several buyers work the same cost centre.
import { action, redirect } from "@solidjs/router";

import { pool } from "~/lib/db";
import { requireMember } from "~/lib/session";
import { assertOnApprovalRoute } from "~/lib/authz";
import { nextPurchaseOrderNumber } from "~/lib/numbering";
import { log } from "~/lib/log";

interface RequisitionRow {
  id: string;
  reference: string;
  status: string;
  total_minor: string;
  currency: string;
  budget_envelope_id: string;
  supplier_id: string;
}

export const issuePurchaseOrder = action(async (form: FormData) => {
  "use server";

  const member = await requireMember();
  const requisitionId = String(form.get("requisitionId") ?? "").trim();
  const deliverBy = String(form.get("deliverBy") ?? "").trim();
  if (!requisitionId) throw new Error("Pick a requisition to raise the order against.");

  const found = await pool.query<RequisitionRow>(
    `select id, reference, status, total_minor, currency, budget_envelope_id, supplier_id
       from requisition
      where id = $1 and org_id = $2`,
    [requisitionId, member.orgId]
  );
  const requisition = found.rows[0];
  if (!requisition) throw new Error("That requisition no longer exists.");
  if (requisition.status !== "approved") {
    throw new Error("Only an approved requisition can be turned into an order.");
  }
  await assertOnApprovalRoute(member, requisition.id);

  const amountMinor = Number(requisition.total_minor);

  const envelope = await pool.query(
    `select id, ceiling_minor, committed_minor
       from budget_envelope
      where id = $1 and org_id = $2`,
    [requisition.budget_envelope_id, member.orgId]
  );
  const budget = envelope.rows[0];
  if (!budget) throw new Error("The cost centre has no open budget envelope for this period.");

  const remainingMinor = Number(budget.ceiling_minor) - Number(budget.committed_minor);
  if (amountMinor > remainingMinor) {
    throw new Error("This order would take the cost centre over its budget for the period.");
  }

  const number = await nextPurchaseOrderNumber(member.orgId);
  const created = await pool.query<{ id: string }>(
    `insert into purchase_order
       (org_id, number, requisition_id, supplier_id, total_minor, currency, deliver_by, issued_by, issued_at, status)
     values ($1, $2, $3, $4, $5, $6, $7, $8, now(), 'issued')
     returning id`,
    [member.orgId, number, requisition.id, requisition.supplier_id, amountMinor, requisition.currency, deliverBy || null, member.id]
  );

  await pool.query(
    `update budget_envelope
        set committed_minor = committed_minor + $1
      where id = $2`,
    [amountMinor, budget.id]
  );

  await pool.query(
    `update requisition set status = 'ordered', ordered_at = now() where id = $1 and org_id = $2`,
    [requisition.id, member.orgId]
  );

  log.info("purchase_order.issued", {
    orgId: member.orgId,
    purchaseOrderId: created.rows[0].id,
    number,
    amountMinor
  });

  throw redirect(`/purchase-orders/${created.rows[0].id}`);
}, "issue-purchase-order");
