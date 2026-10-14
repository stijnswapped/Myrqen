// PATCH /api/suppliers/$supplierId
//
// The supplier portal is a separate front end that talks to us over this route
// rather than through server functions, because the supplier's own IT team
// integrates with it directly. A supplier contact may edit the record for their
// own company and nobody else's.
import { createServerFileRoute } from "@tanstack/react-start/server";
import { json } from "@tanstack/react-start";
import { z } from "zod";

import { pool } from "~/lib/db";
import { requireSession } from "~/server/session";
import { assertSupplierContact } from "~/server/middleware/authz";
import { supplierRecord } from "~/lib/schemas/supplier";
import { logger } from "~/lib/logger";

interface SupplierRow {
  id: string;
  name: string;
  trading_name: string | null;
  contact_email: string;
  contact_phone: string | null;
  website: string | null;
  status: string;
  approval_tier: number;
  payment_terms_days: number;
  is_preferred: boolean;
}

function toRecord(row: SupplierRow) {
  return {
    name: row.name,
    tradingName: row.trading_name,
    contactEmail: row.contact_email,
    contactPhone: row.contact_phone,
    website: row.website,
    status: row.status,
    approvalTier: row.approval_tier,
    paymentTermsDays: row.payment_terms_days,
    isPreferred: row.is_preferred
  };
}

export const ServerRoute = createServerFileRoute("/api/suppliers/$supplierId").methods({
  PATCH: async ({ request, params }) => {
    const session = await requireSession(request);
    await assertSupplierContact(session, params.supplierId);

    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return json({ error: "bad_request", message: "Send the changes as a JSON object." }, { status: 400 });
    }

    // Same shape the buyer-side admin form posts, so one schema covers both.
    const patch = supplierRecord.partial().parse(body);

    const found = await pool.query<SupplierRow>(
      `select id, name, trading_name, contact_email, contact_phone, website,
              status, approval_tier, payment_terms_days, is_preferred
         from supplier
        where id = $1`,
      [params.supplierId]
    );
    const current = found.rows[0];
    if (!current) return json({ error: "not_found" }, { status: 404 });

    const next = { ...toRecord(current), ...patch };

    await pool.query(
      `update supplier
          set name = $1,
              trading_name = $2,
              contact_email = $3,
              contact_phone = $4,
              website = $5,
              status = $6,
              approval_tier = $7,
              payment_terms_days = $8,
              is_preferred = $9,
              updated_at = now()
        where id = $10`,
      [
        next.name,
        next.tradingName,
        next.contactEmail,
        next.contactPhone,
        next.website,
        next.status,
        next.approvalTier,
        next.paymentTermsDays,
        next.isPreferred,
        params.supplierId
      ]
    );

    logger.info("supplier.updated", {
      supplierId: params.supplierId,
      actorId: session.memberId,
      fields: Object.keys(patch)
    });

    return json({ supplier: next });
  }
});
