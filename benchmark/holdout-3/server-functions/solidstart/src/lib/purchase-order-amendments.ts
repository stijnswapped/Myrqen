// Raising the value of an already-issued purchase order.
//
// Same transport as issuing: `action()` over the server-function boundary,
// same envelope, same buyers working the same queue at the same time. The
// difference is that an amendment is nearly always raised while somebody else
// is issuing against the same envelope, so the drawdown is written as one
// conditional statement instead of a read followed by a write.
import { action, redirect } from "@solidjs/router";

import { pool } from "~/lib/db";
import { requireMember } from "~/lib/session";
import { assertOnApprovalRoute } from "~/lib/authz";
import { log } from "~/lib/log";

interface PurchaseOrderRow {
  id: string;
  number: string;
  status: string;
  total_minor: string;
  requisition_id: string;
  budget_envelope_id: string;
}

export const amendPurchaseOrder = action(async (form: FormData) => {
  "use server";

  const member = await requireMember();
  const purchaseOrderId = String(form.get("purchaseOrderId") ?? "").trim();
  const deltaMinor = Number(form.get("deltaMinor") ?? Number.NaN);
  const reason = String(form.get("reason") ?? "").trim();

  if (!purchaseOrderId) throw new Error("Pick an order to amend.");
  if (!Number.isSafeInteger(deltaMinor) || deltaMinor <= 0) {
    throw new Error("Enter the increase as a whole amount in minor units.");
  }
  if (reason.length < 8) throw new Error("Give a reason an auditor will understand.");

  const found = await pool.query<PurchaseOrderRow>(
    `select po.id, po.number, po.status, po.total_minor, po.requisition_id, r.budget_envelope_id
       from purchase_order po
       join requisition r on r.id = po.requisition_id
      where po.id = $1 and po.org_id = $2`,
    [purchaseOrderId, member.orgId]
  );
  const order = found.rows[0];
  if (!order) throw new Error("That order no longer exists.");
  if (order.status !== "issued") throw new Error("Only an open order can be amended.");
  await assertOnApprovalRoute(member, order.requisition_id);

  // Read the envelope first, but only so the failure message can say how much
  // headroom is actually left. The number below is never what the decision is
  // made on — the decision is the `committed_minor + $1 <= ceiling_minor`
  // predicate on the update itself, which the database evaluates against the
  // row it is about to write. Two buyers amending at once therefore serialise:
  // whichever commits second sees the first one's committed_minor and either
  // fits under the ceiling or updates nothing.
  const envelope = await pool.query(
    `select ceiling_minor, committed_minor from budget_envelope where id = $1 and org_id = $2`,
    [order.budget_envelope_id, member.orgId]
  );
  if (envelope.rowCount === 0) throw new Error("The cost centre has no open budget envelope for this period.");
  const headroomMinor = Number(envelope.rows[0].ceiling_minor) - Number(envelope.rows[0].committed_minor);

  const client = await pool.connect();
  try {
    await client.query("begin");

    const drawdown = await client.query(
      `update budget_envelope
          set committed_minor = committed_minor + $1
        where id = $2
          and org_id = $3
          and committed_minor + $1 <= ceiling_minor
      returning committed_minor, ceiling_minor`,
      [deltaMinor, order.budget_envelope_id, member.orgId]
    );

    if (drawdown.rowCount === 0) {
      await client.query("rollback");
      throw new Error(
        `This amendment needs ${deltaMinor} but only ${Math.max(headroomMinor, 0)} is left in the envelope.`
      );
    }

    await client.query(
      `update purchase_order
          set total_minor = total_minor + $1, amended_at = now(), amended_by = $2
        where id = $3 and org_id = $4`,
      [deltaMinor, member.id, order.id, member.orgId]
    );

    await client.query(
      `insert into purchase_order_amendment (purchase_order_id, delta_minor, reason, created_by)
       values ($1, $2, $3, $4)`,
      [order.id, deltaMinor, reason, member.id]
    );

    await client.query("commit");
    log.info("purchase_order.amended", { orgId: member.orgId, purchaseOrderId: order.id, deltaMinor });
  } catch (error) {
    await client.query("rollback").catch(() => {});
    throw error;
  } finally {
    client.release();
  }

  throw redirect(`/purchase-orders/${purchaseOrderId}`);
}, "amend-purchase-order");
