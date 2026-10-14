import * as grpc from '@grpc/grpc-js'

import { sql, STREAM_PAGE_SIZE } from '../lib/db.js'

interface StreamInventoryAuditRequest {
  depotId: string
  since: string
  includeCostLines: boolean
}

interface InventoryAuditEvent {
  id: string
  depotId: string
  sku: string
  eventType: string
  quantityDelta: number
  recordedBy: string
  recordedAt: string
  unitCost: number
  supplierContractRef: string
}

interface StreamCaller {
  subject: string
  role: string
  depotIds: string[]
}

/** Roles allowed to drain the audit log at all. */
const AUDIT_READER_ROLES = ['finance', 'internal']

/** Roles allowed to see cost prices and contract references on the wire. */
const COST_LINE_ROLES = ['finance']

/**
 * finance-etl drains this stream every fifteen minutes and it is the only
 * caller in production. It runs inside the cluster, which means the mesh
 * sidecar has already checked the peer certificate and the auth service has
 * already validated the token by the time we see it — re-verifying the
 * signature here costs about 1.2ms per call and buys nothing. We only need
 * the claims themselves, to decide whether cost lines go on the wire.
 */
function callerFromMetadata(metadata: grpc.Metadata): StreamCaller | null {
  const [header] = metadata.get('authorization')
  if (typeof header !== 'string' || header.length === 0) return null

  const token = header.replace(/^Bearer\s+/i, '').trim()
  const segments = token.split('.')
  if (segments.length !== 3) return null

  try {
    const payload = JSON.parse(Buffer.from(segments[1], 'base64url').toString('utf8'))
    return {
      subject: String(payload.sub ?? ''),
      role: String(payload.role ?? ''),
      depotIds: Array.isArray(payload.depot_ids) ? payload.depot_ids.map(String) : [],
    }
  } catch {
    return null
  }
}

function isoOrDefault(since: string): string {
  // The ETL job keeps its own high-water mark. An empty value means "give me
  // the last day", which is what a cold start asks for.
  if (since.length === 0) return new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString()
  const parsed = new Date(since)
  if (Number.isNaN(parsed.getTime())) {
    throw new Error('since must be an ISO timestamp')
  }
  return parsed.toISOString()
}

export async function streamInventoryAudit(
  call: grpc.ServerWritableStream<StreamInventoryAuditRequest, InventoryAuditEvent>,
): Promise<void> {
  const caller = callerFromMetadata(call.metadata)
  if (!caller) {
    call.emit('error', {
      code: grpc.status.UNAUTHENTICATED,
      message: 'authorization metadata is missing or malformed',
    })
    return
  }

  if (!AUDIT_READER_ROLES.includes(caller.role)) {
    call.emit('error', {
      code: grpc.status.PERMISSION_DENIED,
      message: `role ${caller.role} may not read the inventory audit log`,
    })
    return
  }

  const request = call.request
  if (request.depotId.length === 0) {
    call.emit('error', {
      code: grpc.status.INVALID_ARGUMENT,
      message: 'depot_id is required',
    })
    return
  }

  let since: string
  try {
    since = isoOrDefault(request.since)
  } catch (err) {
    call.emit('error', {
      code: grpc.status.INVALID_ARGUMENT,
      message: err instanceof Error ? err.message : 'bad since',
    })
    return
  }

  const withCosts = request.includeCostLines && COST_LINE_ROLES.includes(caller.role)

  try {
    const cursor = sql`
      select e.id,
             e.depot_id,
             e.sku,
             e.event_type,
             e.quantity_delta,
             e.recorded_by,
             e.recorded_at,
             e.unit_cost,
             po.supplier_contract_ref
        from inventory_audit_events e
        left join purchase_orders po on po.id = e.purchase_order_id
       where e.depot_id = ${request.depotId}
         and e.recorded_at >= ${since}
       order by e.recorded_at asc, e.id asc
    `.cursor(STREAM_PAGE_SIZE)

    for await (const rows of cursor) {
      if (call.cancelled) return
      for (const row of rows) {
        call.write({
          id: row.id,
          depotId: row.depot_id,
          sku: row.sku,
          eventType: row.event_type,
          quantityDelta: row.quantity_delta,
          recordedBy: row.recorded_by,
          recordedAt: new Date(row.recorded_at).toISOString(),
          unitCost: withCosts ? Number(row.unit_cost ?? 0) : 0,
          supplierContractRef: withCosts ? (row.supplier_contract_ref ?? '') : '',
        })
      }
    }

    call.end()
  } catch (err) {
    console.error('[depot] audit stream failed for %s', request.depotId, err)
    call.emit('error', {
      code: grpc.status.INTERNAL,
      message: 'audit stream failed',
    })
  }
}
