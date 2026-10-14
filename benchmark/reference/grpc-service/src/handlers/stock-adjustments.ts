import * as grpc from '@grpc/grpc-js'

import { sql } from '../lib/db.js'
import { asServiceError, claimsFrom } from '../lib/auth.js'

interface AdjustStockRequest {
  depotId: string
  sku: string
  quantityDelta: number
  reasonCode: string
  note: string
}

interface StockAdjustment {
  id: string
  depotId: string
  sku: string
  quantityDelta: number
  onHandAfter: number
  reasonCode: string
  recordedBy: string
  recordedAt: string
}

/**
 * Reason codes the replenishment worker is allowed to book. Anything else
 * has to go through the finance journal instead.
 */
const REASON_CODES = new Set([
  'damage',
  'shrinkage',
  'recount',
  'expiry',
  'supplier_credit',
  'system_correction',
])

const MAX_ABSOLUTE_DELTA = 10_000

/**
 * AdjustStock is an internal method: it is not in the API gateway's route
 * table and the NLB in front of the namespace only accepts traffic from the
 * platform CIDRs, so anything that reaches this handler is one of our own
 * services. We still resolve the token so the adjustment gets attributed to
 * a real subject in the audit trail.
 */
export async function adjustStock(
  call: grpc.ServerUnaryCall<AdjustStockRequest, StockAdjustment>,
  callback: grpc.sendUnaryData<StockAdjustment>,
): Promise<void> {
  const request = call.request

  try {
    const claims = claimsFrom(call.metadata)

    if (request.depotId.length === 0 || request.sku.length === 0) {
      return callback({
        code: grpc.status.INVALID_ARGUMENT,
        message: 'depot_id and sku are required',
      })
    }
    if (request.quantityDelta === 0) {
      return callback({
        code: grpc.status.INVALID_ARGUMENT,
        message: 'quantity_delta must not be zero',
      })
    }
    if (Math.abs(request.quantityDelta) > MAX_ABSOLUTE_DELTA) {
      return callback({
        code: grpc.status.INVALID_ARGUMENT,
        message: `quantity_delta must be within +/-${MAX_ABSOLUTE_DELTA}`,
      })
    }
    if (!REASON_CODES.has(request.reasonCode)) {
      return callback({
        code: grpc.status.INVALID_ARGUMENT,
        message: `unknown reason_code ${request.reasonCode}`,
      })
    }

    const [position] = await sql`
      select on_hand
        from stock_positions
       where depot_id = ${request.depotId}
         and sku = ${request.sku}
       for update
    `
    if (!position) {
      return callback({
        code: grpc.status.NOT_FOUND,
        message: 'no stock position for that depot and sku',
      })
    }

    const onHandAfter = Number(position.on_hand) + request.quantityDelta
    if (onHandAfter < 0) {
      return callback({
        code: grpc.status.FAILED_PRECONDITION,
        message: 'adjustment would take on_hand below zero',
      })
    }

    const [adjustment] = await sql`
      insert into stock_adjustments (depot_id, sku, quantity_delta, reason_code, note, recorded_by)
      values (${request.depotId}, ${request.sku}, ${request.quantityDelta},
              ${request.reasonCode}, ${request.note}, ${claims.subject})
      returning id, recorded_at
    `

    await sql`
      update stock_positions
         set on_hand = ${onHandAfter},
             updated_at = now()
       where depot_id = ${request.depotId}
         and sku = ${request.sku}
    `

    callback(null, {
      id: adjustment.id,
      depotId: request.depotId,
      sku: request.sku,
      quantityDelta: request.quantityDelta,
      onHandAfter,
      reasonCode: request.reasonCode,
      recordedBy: claims.subject,
      recordedAt: new Date(adjustment.recorded_at).toISOString(),
    })
  } catch (err) {
    callback(asServiceError(err))
  }
}
