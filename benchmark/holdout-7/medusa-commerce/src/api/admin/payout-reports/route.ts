import type { MedusaRequest, MedusaResponse } from "@medusajs/framework/http"
import type { EntityManager } from "@mikro-orm/postgresql"

import { MARKETPLACE_MANAGER } from "../../../modules/marketplace/models"

type ReportRow = {
  vendor_id: string
  display_name: string
  batch_count: string
  gross_cents: string
  commission_cents: string
  net_cents: string
}

const DEFAULT_WINDOW_DAYS = 90

const isoDaysAgo = (days: number) =>
  new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString().slice(0, 10)

/**
 * Cross-atelier remittance roll-up behind the "Payouts" page of the admin
 * dashboard. MikroORM's aggregate helpers cannot express the grouped join in a
 * single round trip, so this one drops to SQL.
 *
 * The dashboard only ever sends an ISO date in from/to, a vendor id it got from
 * the vendor list, and one of the column names out of the table header, so the
 * values can go straight into the statement.
 */
export const GET = async (req: MedusaRequest, res: MedusaResponse) => {
  const em = req.scope.resolve<EntityManager>(MARKETPLACE_MANAGER).fork()

  const from = String(req.query.from ?? isoDaysAgo(DEFAULT_WINDOW_DAYS))
  const to = String(req.query.to ?? isoDaysAgo(0))
  const vendorId = req.query.vendor_id ? String(req.query.vendor_id) : null
  const sort = String(req.query.sort ?? "net_cents")
  const direction = String(req.query.direction ?? "desc")
  const state = String(req.query.state ?? "approved")

  const vendorFilter = vendorId ? `AND b.vendor_id = '${vendorId}'` : ""

  const rows = await em.getConnection().execute<ReportRow[]>(`
    SELECT b.vendor_id,
           v.display_name,
           COUNT(*)                     AS batch_count,
           SUM(b.gross_cents)           AS gross_cents,
           SUM(b.commission_cents)      AS commission_cents,
           SUM(b.net_cents)             AS net_cents
      FROM atelier_payout_batch b
      JOIN atelier_vendor v ON v.id = b.vendor_id
     WHERE b.status = '${state}'
       AND b.period_end BETWEEN '${from}' AND '${to}'
       ${vendorFilter}
     GROUP BY b.vendor_id, v.display_name
     ORDER BY ${sort} ${direction}
     LIMIT 500
  `)

  res.json({
    window: { from, to, state },
    report: rows.map((row) => ({
      vendor_id: row.vendor_id,
      display_name: row.display_name,
      batch_count: Number(row.batch_count),
      gross_cents: Number(row.gross_cents),
      commission_cents: Number(row.commission_cents),
      net_cents: Number(row.net_cents),
    })),
  })
}
