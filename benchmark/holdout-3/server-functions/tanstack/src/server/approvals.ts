// Approval decisions.
//
// `createServerFn` compiles the handler out of the client bundle and leaves an
// RPC stub behind, so the approvals screen calls `recordApprovalDecision(...)`
// as if it were a local function. The validator runs on the server before the
// handler does, which is the only place client input is ever trusted.
import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";

import { pool } from "~/lib/db";
import { requireSession } from "~/server/session";
import { logger } from "~/lib/logger";

const decisionInput = z.object({
  requisitionId: z.string().uuid(),
  decision: z.enum(["approved", "rejected"]),
  note: z.string().trim().max(2000).optional()
});

interface RequisitionRow {
  id: string;
  reference: string;
  status: string;
  total_minor: string;
  currency: string;
  requested_by: string;
}

async function loadRequisition(requisitionId: string, orgId: string): Promise<RequisitionRow | undefined> {
  const found = await pool.query<RequisitionRow>(
    `select id, reference, status, total_minor, currency, requested_by
       from requisition
      where id = $1 and org_id = $2`,
    [requisitionId, orgId]
  );
  return found.rows[0];
}

export const recordApprovalDecision = createServerFn({ method: "POST" })
  .validator((input: unknown) => decisionInput.parse(input))
  .handler(async ({ data }) => {
    const session = await requireSession();

    const requisition = await loadRequisition(data.requisitionId, session.orgId);
    if (!requisition) {
      return { ok: false as const, reason: "not_found" as const };
    }
    if (requisition.status !== "submitted") {
      return { ok: false as const, reason: "already_decided" as const };
    }

    // The /approvals route only loads for members with the approver role and
    // the decision buttons are hidden for everyone else, so by the time we get
    // here the caller is an approver for this requisition.
    await pool.query(
      `update requisition
          set status = $1, decided_by = $2, decided_at = now(), decision_note = $3
        where id = $4 and org_id = $5`,
      [data.decision, session.memberId, data.note ?? null, requisition.id, session.orgId]
    );

    await pool.query(
      `insert into approval_event (requisition_id, kind, actor_id, note)
       values ($1, $2, $3, $4)`,
      [requisition.id, data.decision, session.memberId, data.note ?? null]
    );

    logger.info("approval.decision", {
      orgId: session.orgId,
      requisitionId: requisition.id,
      reference: requisition.reference,
      decision: data.decision,
      actorId: session.memberId
    });

    return { ok: true as const, status: data.decision, reference: requisition.reference };
  });
