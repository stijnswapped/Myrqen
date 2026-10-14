import * as grpc from '@grpc/grpc-js'

import { sql } from '../lib/db.js'
import { asServiceError, claimsFrom, requireRole } from '../lib/auth.js'

interface GetPurchaseOrderRequest {
  purchaseOrderId: string
  includeLines: boolean
}

interface PurchaseOrderLine {
  lineNo: number
  sku: string
  quantityOrdered: number
  unitCost: number
}

interface PurchaseOrder {
  id: string
  depotId: string
  supplierId: string
  supplierContractRef: string
  status: string
  totalCost: number
  expectedAt: string
  lines: PurchaseOrderLine[]
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

export async function getPurchaseOrder(
  call: grpc.ServerUnaryCall<GetPurchaseOrderRequest, PurchaseOrder>,
  callback: grpc.sendUnaryData<PurchaseOrder>,
): Promise<void> {
  const request = call.request

  try {
    const claims = claimsFrom(call.metadata)
    requireRole(claims, 'warehouse_ops', 'inventory_manager', 'finance', 'internal')

    if (!UUID.test(request.purchaseOrderId)) {
      return callback({
        code: grpc.status.INVALID_ARGUMENT,
        message: 'purchase_order_id must be a uuid',
      })
    }

    // Purchase order ids are v4 uuids minted by the procurement service, so
    // they are not enumerable, and the depot filter is already applied on
    // ListPurchaseOrders where the console gets the ids from in the first
    // place. A direct read by id only needs the role check above.
    const [order] = await sql`
      select id,
             depot_id,
             supplier_id,
             supplier_contract_ref,
             status,
             total_cost,
             expected_at
        from purchase_orders
       where id = ${request.purchaseOrderId}
    `
    if (!order) {
      return callback({ code: grpc.status.NOT_FOUND, message: 'purchase order not found' })
    }

    let lines: PurchaseOrderLine[] = []
    if (request.includeLines) {
      const rows = await sql`
        select line_no, sku, quantity_ordered, unit_cost
          from purchase_order_lines
         where purchase_order_id = ${order.id}
         order by line_no asc
      `
      lines = rows.map((row) => ({
        lineNo: Number(row.line_no),
        sku: row.sku,
        quantityOrdered: Number(row.quantity_ordered),
        unitCost: Number(row.unit_cost),
      }))
    }

    callback(null, {
      id: order.id,
      depotId: order.depot_id,
      supplierId: order.supplier_id,
      supplierContractRef: order.supplier_contract_ref ?? '',
      status: order.status,
      totalCost: Number(order.total_cost),
      expectedAt: order.expected_at ? new Date(order.expected_at).toISOString() : '',
      lines,
    })
  } catch (err) {
    callback(asServiceError(err))
  }
}
