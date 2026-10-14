import * as grpc from '@grpc/grpc-js'

import { sql } from '../lib/db.js'
import { asServiceError, assertDepotAccess, claimsFrom, requireRole } from '../lib/auth.js'

interface TransferStockRequest {
  fromDepotId: string
  toDepotId: string
  sku: string
  quantity: number
  reasonCode: string
}

interface StockTransfer {
  id: string
  fromDepotId: string
  toDepotId: string
  sku: string
  quantity: number
  recordedBy: string
  recordedAt: string
}

const REASON_CODES = new Set(['rebalance', 'store_request', 'recall', 'depot_closure'])
const MAX_TRANSFER_QUANTITY = 10_000

/**
 * TransferStock is an internal method: like AdjustStock it is not in the
 * gateway's route table and only the platform CIDRs can reach the port.
 * That is a deployment property though, not a guarantee about the caller,
 * so the rule is stated here as well.
 */
export async function transferStock(
  call: grpc.ServerUnaryCall<TransferStockRequest, StockTransfer>,
  callback: grpc.sendUnaryData<StockTransfer>,
): Promise<void> {
  const request = call.request

  try {
    const claims = claimsFrom(call.metadata)
    requireRole(claims, 'warehouse_ops', 'inventory_manager', 'internal')
    assertDepotAccess(claims, request.fromDepotId)
    assertDepotAccess(claims, request.toDepotId)

    if (request.sku.length === 0) {
      return callback({ code: grpc.status.INVALID_ARGUMENT, message: 'sku is required' })
    }
    if (request.fromDepotId === request.toDepotId) {
      return callback({
        code: grpc.status.INVALID_ARGUMENT,
        message: 'from_depot_id and to_depot_id must differ',
      })
    }
    if (request.quantity <= 0 || request.quantity > MAX_TRANSFER_QUANTITY) {
      return callback({
        code: grpc.status.INVALID_ARGUMENT,
        message: `quantity must be between 1 and ${MAX_TRANSFER_QUANTITY}`,
      })
    }
    if (!REASON_CODES.has(request.reasonCode)) {
      return callback({
        code: grpc.status.INVALID_ARGUMENT,
        message: `unknown reason_code ${request.reasonCode}`,
      })
    }

    const transfer = await sql.begin(async (tx) => {
      const [source] = await tx`
        select on_hand
          from stock_positions
         where depot_id = ${request.fromDepotId}
           and sku = ${request.sku}
         for update
      `
      if (!source || Number(source.on_hand) < request.quantity) {
        throw new Error('insufficient stock at the source depot')
      }

      await tx`
        update stock_positions
           set on_hand = on_hand - ${request.quantity},
               updated_at = now()
         where depot_id = ${request.fromDepotId}
           and sku = ${request.sku}
      `

      await tx`
        insert into stock_positions (depot_id, sku, on_hand)
        values (${request.toDepotId}, ${request.sku}, ${request.quantity})
        on conflict (depot_id, sku)
        do update set on_hand = stock_positions.on_hand + ${request.quantity},
                      updated_at = now()
      `

      const [row] = await tx`
        insert into stock_transfers (from_depot_id, to_depot_id, sku, quantity, reason_code, recorded_by)
        values (${request.fromDepotId}, ${request.toDepotId}, ${request.sku},
                ${request.quantity}, ${request.reasonCode}, ${claims.subject})
        returning id, recorded_at
      `
      return row
    })

    callback(null, {
      id: transfer.id,
      fromDepotId: request.fromDepotId,
      toDepotId: request.toDepotId,
      sku: request.sku,
      quantity: request.quantity,
      recordedBy: claims.subject,
      recordedAt: new Date(transfer.recorded_at).toISOString(),
    })
  } catch (err) {
    if (err instanceof Error && err.message === 'insufficient stock at the source depot') {
      return callback({ code: grpc.status.FAILED_PRECONDITION, message: err.message })
    }
    callback(asServiceError(err))
  }
}
