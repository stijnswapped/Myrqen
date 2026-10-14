// Approval delegation ("out of office" cover).
//
// Same server-function transport as the decision endpoint: RPC stub on the
// client, validator then handler on the server. Authorisation is attached to
// the function rather than written into the body — `requireApprover` runs
// before the validator and puts the resolved approver on `context`, so the
// handler can assume it exists and read the caller's own limit from it.
import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";

import { pool } from "~/lib/db";
import { requireApprover } from "~/server/middleware/authz";
import { logger } from "~/lib/logger";

const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

const delegationInput = z
  .object({
    delegateMemberId: z.string().uuid(),
    from: z.string().regex(ISO_DATE),
    to: z.string().regex(ISO_DATE),
    ceilingMinor: z.number().int().positive()
  })
  .refine((value) => value.from <= value.to, { message: "The cover period ends before it starts." });

export const openDelegation = createServerFn({ method: "POST" })
  .middleware([requireApprover])
  .validator((input: unknown) => delegationInput.parse(input))
  .handler(async ({ data, context }) => {
    const { approver } = context;

    // A delegate can never be handed more authority than the approver holds,
    // and cover is only ever granted to somebody inside the same organisation.
    const ceilingMinor = Math.min(data.ceilingMinor, approver.limitMinor);

    const delegate = await pool.query<{ id: string; display_name: string }>(
      `select id, display_name
         from member
        where id = $1 and org_id = $2 and status = 'active'`,
      [data.delegateMemberId, approver.orgId]
    );
    if (delegate.rowCount === 0) {
      return { ok: false as const, reason: "unknown_delegate" as const };
    }
    if (data.delegateMemberId === approver.memberId) {
      return { ok: false as const, reason: "self_delegation" as const };
    }

    const created = await pool.query<{ id: string }>(
      `insert into approval_delegation
         (org_id, approver_id, delegate_id, valid_from, valid_to, ceiling_minor, created_by)
       values ($1, $2, $3, $4, $5, $6, $2)
       on conflict (org_id, approver_id, valid_from) do update
         set delegate_id = excluded.delegate_id,
             valid_to = excluded.valid_to,
             ceiling_minor = excluded.ceiling_minor
       returning id`,
      [approver.orgId, approver.memberId, data.delegateMemberId, data.from, data.to, ceilingMinor]
    );

    logger.info("approval.delegation.opened", {
      orgId: approver.orgId,
      approverId: approver.memberId,
      delegationId: created.rows[0].id,
      ceilingMinor
    });

    return {
      ok: true as const,
      delegationId: created.rows[0].id,
      delegateName: delegate.rows[0].display_name,
      ceilingMinor
    };
  });
