// PATCH /api/cost-centres/$costCentreId
//
// Same integration surface as the supplier route: a JSON PATCH the finance
// team's spreadsheet tooling posts directly, authorised per record. A cost
// centre carries controls the owner must never move — its budget ceiling and
// its delegated approval limit are set by finance, not by the owner — so the
// body is narrowed to the editable fields before it is merged.
import { createServerFileRoute } from "@tanstack/react-start/server";
import { json } from "@tanstack/react-start";
import { z } from "zod";

import { pool } from "~/lib/db";
import { requireSession } from "~/server/session";
import { assertCostCentreOwner } from "~/server/middleware/authz";
import { logger } from "~/lib/logger";

interface CostCentreRow {
  id: string;
  code: string;
  name: string;
  owner_email: string;
  notify_email: string | null;
  status: string;
  ceiling_minor: string;
  approval_limit_minor: string;
}

/**
 * The three things an owner may change. `.strict()` makes an unknown key a 400
 * rather than something that quietly rides along into the merge below.
 */
const ownerEditable = z
  .object({
    name: z.string().trim().min(2).max(120),
    ownerEmail: z.string().email(),
    notifyEmail: z.string().email().nullable()
  })
  .partial()
  .strict();

function toRecord(row: CostCentreRow) {
  return {
    code: row.code,
    name: row.name,
    ownerEmail: row.owner_email,
    notifyEmail: row.notify_email,
    status: row.status,
    ceilingMinor: Number(row.ceiling_minor),
    approvalLimitMinor: Number(row.approval_limit_minor)
  };
}

export const ServerRoute = createServerFileRoute("/api/cost-centres/$costCentreId").methods({
  PATCH: async ({ request, params }) => {
    const session = await requireSession(request);
    await assertCostCentreOwner(session, params.costCentreId);

    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return json({ error: "bad_request", message: "Send the changes as a JSON object." }, { status: 400 });
    }

    const parsed = ownerEditable.safeParse(body);
    if (!parsed.success) {
      return json({ error: "bad_request", issues: parsed.error.issues.map((issue) => issue.path.join(".")) }, { status: 400 });
    }
    const patch = parsed.data;

    const found = await pool.query<CostCentreRow>(
      `select id, code, name, owner_email, notify_email, status, ceiling_minor, approval_limit_minor
         from cost_centre
        where id = $1 and org_id = $2`,
      [params.costCentreId, session.orgId]
    );
    const current = found.rows[0];
    if (!current) return json({ error: "not_found" }, { status: 404 });

    const next = { ...toRecord(current), ...patch };

    await pool.query(
      `update cost_centre
          set name = $1,
              owner_email = $2,
              notify_email = $3,
              status = $4,
              ceiling_minor = $5,
              approval_limit_minor = $6,
              updated_at = now()
        where id = $7 and org_id = $8`,
      [
        next.name,
        next.ownerEmail,
        next.notifyEmail,
        next.status,
        next.ceilingMinor,
        next.approvalLimitMinor,
        params.costCentreId,
        session.orgId
      ]
    );

    logger.info("cost_centre.updated", {
      orgId: session.orgId,
      costCentreId: params.costCentreId,
      actorId: session.memberId,
      fields: Object.keys(patch)
    });

    return json({ costCentre: next });
  }
});
