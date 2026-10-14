import * as grpc from '@grpc/grpc-js'

import { sql } from '../lib/db.js'
import { asServiceError, assertDepotAccess, claimsFrom, requireRole } from '../lib/auth.js'

interface ApproveCycleCountRequest {
  cycleCountId: string
  depotId: string
  actorUserId: string
  note: string
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

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

export async function approveCycleCount(
  call: grpc.ServerUnaryCall<ApproveCycleCountRequest, CycleCount>,
  callback: grpc.sendUnaryData<CycleCount>,
): Promise<void> {
  const request = call.request

  try {
    const claims = claimsFrom(call.metadata)
    requireRole(claims, 'inventory_manager', 'internal')
    assertDepotAccess(claims, request.depotId)

    if (!UUID.test(request.cycleCountId)) {
      return callback({
        code: grpc.status.INVALID_ARGUMENT,
        message: 'cycle_count_id must be a uuid',
      })
    }

    // By default the approver is whoever the token belongs to. The terminal
    // BFF may approve on behalf of a supervisor standing at a shared
    // terminal, but only the BFF's own service role is allowed to name
    // somebody else, and the named supervisor must hold the approval
    // entitlement in this depot themselves.
    //
    // Note the length test: proto3 gives us '' for a field the caller never
    // set, never undefined, so emptiness is what "not supplied" looks like.
    let approverId = claims.subject
    if (request.actorUserId.length > 0) {
      requireRole(claims, 'internal')
      const [delegate] = await sql`
        select staff_id
          from staff_entitlements
         where staff_id = ${request.actorUserId}
           and depot_id = ${request.depotId}
           and entitlement = 'cycle_count_approval'
           and revoked_at is null
      `
      if (!delegate) {
        return callback({
          code: grpc.status.PERMISSION_DENIED,
          message: 'named approver has no cycle_count_approval entitlement for that depot',
        })
      }
      approverId = delegate.staff_id
    }

    const [count] = await sql`
      select id, depot_id, sku, counted_quantity, expected_quantity, status, counted_by, counted_at
        from cycle_counts
       where id = ${request.cycleCountId}
         and depot_id = ${request.depotId}
    `
    if (!count) {
      return callback({ code: grpc.status.NOT_FOUND, message: 'cycle count not found' })
    }
    if (count.status !== 'awaiting_approval') {
      return callback({
        code: grpc.status.FAILED_PRECONDITION,
        message: `cycle count is ${count.status}`,
      })
    }
    // Dual control: the person who counted may not approve their own count.
    if (count.counted_by === approverId) {
      return callback({
        code: grpc.status.FAILED_PRECONDITION,
        message: 'a cycle count must be approved by somebody other than the counter',
      })
    }

    await sql`
      update cycle_counts
         set status = 'approved',
             approved_by = ${approverId},
             approval_note = ${request.note},
             approved_at = now()
       where id = ${count.id}
    `

    callback(null, {
      id: count.id,
      depotId: count.depot_id,
      sku: count.sku,
      countedQuantity: Number(count.counted_quantity),
      expectedQuantity: Number(count.expected_quantity),
      status: 'approved',
      countedBy: count.counted_by,
      approvedBy: approverId,
      countedAt: new Date(count.counted_at).toISOString(),
    })
  } catch (err) {
    callback(asServiceError(err))
  }
}
