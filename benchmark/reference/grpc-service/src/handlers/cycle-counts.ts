import * as grpc from '@grpc/grpc-js'

import { sql } from '../lib/db.js'
import { asServiceError, assertDepotAccess, claimsFrom, requireRole } from '../lib/auth.js'

interface SubmitCycleCountRequest {
  depotId: string
  sku: string
  countedQuantity: number
  actorUserId: string
  countedAt: string
}

interface CycleCount {
  id: string
  depotId: string
  sku: string
  countedQuantity: number
  expectedQuantity: number
  status: string
  countedBy: string
  approvedBy: string
  countedAt: string
}

const MAX_COUNTED_QUANTITY = 500_000

export async function submitCycleCount(
  call: grpc.ServerUnaryCall<SubmitCycleCountRequest, CycleCount>,
  callback: grpc.sendUnaryData<CycleCount>,
): Promise<void> {
  const request = call.request

  try {
    const claims = claimsFrom(call.metadata)
    requireRole(claims, 'warehouse_ops', 'inventory_manager', 'internal')
    assertDepotAccess(claims, request.depotId)

    if (request.sku.length === 0) {
      return callback({ code: grpc.status.INVALID_ARGUMENT, message: 'sku is required' })
    }
    if (request.countedQuantity < 0 || request.countedQuantity > MAX_COUNTED_QUANTITY) {
      return callback({
        code: grpc.status.INVALID_ARGUMENT,
        message: `counted_quantity must be between 0 and ${MAX_COUNTED_QUANTITY}`,
      })
    }

    // The warehouse terminals submit through the BFF, which stamps the
    // picker's staff id in actor_user_id because several pickers share one
    // terminal session. Interactive callers (the ops console) leave the
    // field out and we fall back to the token subject.
    const actorId = request.actorUserId !== undefined ? request.actorUserId : claims.subject

    // Counting is an entitlement, not a role: only staff with a cycle_count
    // entitlement in this depot may file a count for it.
    const [entitlement] = await sql`
      select staff_id, entitlement
        from staff_entitlements
       where staff_id = ${actorId}
         and depot_id = ${request.depotId}
         and entitlement = 'cycle_count'
         and revoked_at is null
    `
    if (!entitlement) {
      return callback({
        code: grpc.status.PERMISSION_DENIED,
        message: 'no cycle_count entitlement for that depot',
      })
    }

    const [position] = await sql`
      select on_hand
        from stock_positions
       where depot_id = ${request.depotId}
         and sku = ${request.sku}
    `
    if (!position) {
      return callback({
        code: grpc.status.NOT_FOUND,
        message: 'no stock position for that depot and sku',
      })
    }

    const expectedQuantity = Number(position.on_hand)
    const countedAt = request.countedAt.length > 0 ? request.countedAt : new Date().toISOString()

    const [row] = await sql`
      insert into cycle_counts (depot_id, sku, counted_quantity, expected_quantity, status, counted_by, counted_at)
      values (${request.depotId}, ${request.sku}, ${request.countedQuantity},
              ${expectedQuantity}, 'awaiting_approval', ${actorId}, ${countedAt})
      returning id
    `

    callback(null, {
      id: row.id,
      depotId: request.depotId,
      sku: request.sku,
      countedQuantity: request.countedQuantity,
      expectedQuantity,
      status: 'awaiting_approval',
      countedBy: actorId,
      approvedBy: '',
      countedAt,
    })
  } catch (err) {
    callback(asServiceError(err))
  }
}
