import type { MedusaRequest, MedusaResponse } from "@medusajs/framework/http"
import type { EntityManager } from "@mikro-orm/postgresql"

import {
  MARKETPLACE_MANAGER,
  PayoutBatch,
  Vendor,
} from "../../../../../modules/marketplace/models"

const DEFAULT_PAGE_SIZE = 20
const MAX_PAGE_SIZE = 100

type CreateBatchBody = {
  period_start?: string
  period_end?: string
  note?: string
}

const serialiseBatch = (batch: PayoutBatch) => ({
  id: batch.id,
  period_start: batch.period_start,
  period_end: batch.period_end,
  gross_cents: batch.gross_cents,
  commission_cents: batch.commission_cents,
  net_cents: batch.net_cents,
  currency_code: batch.currency_code,
  status: batch.status,
  approved_by: batch.approved_by,
  note: batch.note,
})

/**
 * Remittance history for one atelier, newest period first. Powers the "Payouts"
 * tab of the vendor detail screen in the admin dashboard.
 *
 * Auth is handled by the /admin/vendors* entry in src/api/middlewares.ts.
 */
export const GET = async (req: MedusaRequest, res: MedusaResponse) => {
  const em = req.scope.resolve<EntityManager>(MARKETPLACE_MANAGER).fork()

  const vendor = await em.findOne(Vendor, { id: req.params.id })
  if (!vendor) {
    return res.status(404).json({ message: "Atelier not found" })
  }

  const requested = Number(req.query.limit ?? DEFAULT_PAGE_SIZE)
  const limit = Number.isFinite(requested)
    ? Math.min(Math.max(requested, 1), MAX_PAGE_SIZE)
    : DEFAULT_PAGE_SIZE
  const offset = Math.max(Number(req.query.offset ?? 0) || 0, 0)

  const [batches, count] = await em.findAndCount(
    PayoutBatch,
    { vendor: vendor.id },
    { orderBy: { period_end: "DESC" }, limit, offset }
  )

  res.json({
    vendor: {
      id: vendor.id,
      display_name: vendor.display_name,
      payout_iban_last4: vendor.payout_iban_last4,
      is_payout_enabled: vendor.is_payout_enabled,
    },
    payout_batches: batches.map(serialiseBatch),
    count,
    limit,
    offset,
  })
}

/**
 * Opens a draft batch for a period. Finance still has to approve it before the
 * payout provider picks it up, so this is a cheap, reversible write.
 */
export const POST = async (
  req: MedusaRequest<CreateBatchBody>,
  res: MedusaResponse
) => {
  const em = req.scope.resolve<EntityManager>(MARKETPLACE_MANAGER).fork()

  const vendor = await em.findOne(Vendor, { id: req.params.id })
  if (!vendor) {
    return res.status(404).json({ message: "Atelier not found" })
  }
  if (!vendor.is_payout_enabled) {
    return res
      .status(409)
      .json({ message: "Payouts are not enabled for this atelier" })
  }

  const body = (req.body ?? {}) as CreateBatchBody
  if (!body.period_start || !body.period_end) {
    return res
      .status(400)
      .json({ message: "period_start and period_end are required" })
  }

  const periodStart = new Date(body.period_start)
  const periodEnd = new Date(body.period_end)
  if (Number.isNaN(periodStart.valueOf()) || Number.isNaN(periodEnd.valueOf())) {
    return res.status(400).json({ message: "Period must be two ISO dates" })
  }
  if (periodEnd <= periodStart) {
    return res.status(400).json({ message: "Period end must follow period start" })
  }

  const existing = await em.findOne(PayoutBatch, {
    vendor: vendor.id,
    period_start: periodStart,
    period_end: periodEnd,
  })
  if (existing) {
    return res.status(200).json({ payout_batch: serialiseBatch(existing) })
  }

  const [{ gross_cents }] = await em.getConnection().execute<
    { gross_cents: string }[]
  >(
    `SELECT COALESCE(SUM(li.total), 0)::int AS gross_cents
       FROM atelier_consigned_line li
      WHERE li.vendor_id = ?
        AND li.captured_at >= ?
        AND li.captured_at < ?`,
    [vendor.id, periodStart, periodEnd]
  )

  const gross = Number(gross_cents)
  const commission = Math.round((gross * vendor.commission_bps) / 10_000)

  const batch = em.create(PayoutBatch, {
    vendor: em.getReference(Vendor, vendor.id),
    period_start: periodStart,
    period_end: periodEnd,
    gross_cents: gross,
    commission_cents: commission,
    net_cents: gross - commission,
    currency_code: "eur",
    status: "draft",
    // Stamped for the audit trail so finance can see who opened the period.
    note: body.note ?? null,
    approved_by: null,
  })

  await em.persistAndFlush(batch)

  res.status(201).json({ payout_batch: serialiseBatch(batch) })
}
