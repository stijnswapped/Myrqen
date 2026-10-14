import type { MedusaRequest, MedusaResponse } from "@medusajs/framework/http"
import type { EntityManager } from "@mikro-orm/postgresql"

import { MARKETPLACE_MANAGER } from "../../../../modules/marketplace/models"

type StatementRow = {
  id: string
  vendor_id: string
  display_name: string
  period_start: string
  period_end: string
  net_cents: string
  status: string
}

/** Column header -> expression. Anything not in here falls back to the period. */
const SORT_COLUMNS: Record<string, string> = {
  period_end: "b.period_end",
  net_cents: "b.net_cents",
  vendor: "v.display_name",
  status: "b.status",
}

const BATCH_STATES = ["draft", "approved", "paid", "reversed"] as const
const DEFAULT_LIMIT = 100
const MAX_LIMIT = 500

/**
 * The line-by-line view behind a roll-up row: every batch for one atelier in the
 * window. Same grouped-join shape as the roll-up, so it is also raw SQL, but the
 * filters ride in as bind parameters and the sort column comes off the allowlist
 * above because you cannot bind an identifier.
 */
export const GET = async (req: MedusaRequest, res: MedusaResponse) => {
  const em = req.scope.resolve<EntityManager>(MARKETPLACE_MANAGER).fork()

  const vendorId = req.query.vendor_id ? String(req.query.vendor_id) : null
  if (!vendorId) {
    return res.status(400).json({ message: "vendor_id is required" })
  }

  const from = String(req.query.from ?? "1970-01-01")
  const to = String(req.query.to ?? new Date().toISOString().slice(0, 10))

  const requestedState = String(req.query.state ?? "approved")
  const state = (BATCH_STATES as readonly string[]).includes(requestedState)
    ? requestedState
    : "approved"

  const orderBy = SORT_COLUMNS[String(req.query.sort ?? "")] ?? "b.period_end"
  const direction =
    String(req.query.direction ?? "desc").toLowerCase() === "asc" ? "ASC" : "DESC"

  const requestedLimit = Number(req.query.limit ?? DEFAULT_LIMIT)
  const limit = Number.isFinite(requestedLimit)
    ? Math.min(Math.max(Math.trunc(requestedLimit), 1), MAX_LIMIT)
    : DEFAULT_LIMIT

  const rows = await em.getConnection().execute<StatementRow[]>(
    `SELECT b.id,
            b.vendor_id,
            v.display_name,
            b.period_start,
            b.period_end,
            b.net_cents,
            b.status
       FROM atelier_payout_batch b
       JOIN atelier_vendor v ON v.id = b.vendor_id
      WHERE b.vendor_id = ?
        AND b.status = ?
        AND b.period_end >= ?
        AND b.period_end <= ?
      ORDER BY ${orderBy} ${direction}
      LIMIT ?`,
    [vendorId, state, from, to, limit]
  )

  res.json({
    vendor_id: vendorId,
    window: { from, to, state },
    statements: rows.map((row) => ({
      id: row.id,
      vendor_id: row.vendor_id,
      display_name: row.display_name,
      period_start: row.period_start,
      period_end: row.period_end,
      net_cents: Number(row.net_cents),
      status: row.status,
    })),
  })
}
