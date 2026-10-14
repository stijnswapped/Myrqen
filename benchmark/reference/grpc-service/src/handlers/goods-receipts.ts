import * as grpc from '@grpc/grpc-js'

import { sql } from '../lib/db.js'
import { asServiceError, assertDepotAccess, claimsFrom, requireRole } from '../lib/auth.js'

interface GetGoodsReceiptRequest {
  goodsReceiptId: string
}

interface GoodsReceiptLine {
  lineNo: number
  sku: string
  quantityReceived: number
  quantityRejected: number
}

interface GoodsReceipt {
  id: string
  depotId: string
  purchaseOrderId: string
  receivedAt: string
  receivedBy: string
  lines: GoodsReceiptLine[]
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

export async function getGoodsReceipt(
  call: grpc.ServerUnaryCall<GetGoodsReceiptRequest, GoodsReceipt>,
  callback: grpc.sendUnaryData<GoodsReceipt>,
): Promise<void> {
  const request = call.request

  try {
    const claims = claimsFrom(call.metadata)
    requireRole(claims, 'warehouse_ops', 'inventory_manager', 'finance', 'internal')

    if (!UUID.test(request.goodsReceiptId)) {
      return callback({
        code: grpc.status.INVALID_ARGUMENT,
        message: 'goods_receipt_id must be a uuid',
      })
    }

    const [receipt] = await sql`
      select id, depot_id, purchase_order_id, received_at, received_by
        from goods_receipts
       where id = ${request.goodsReceiptId}
    `
    if (!receipt) {
      return callback({ code: grpc.status.NOT_FOUND, message: 'goods receipt not found' })
    }

    // The id says nothing about who may read the row, so the depot on the
    // row is checked against the caller's scope before anything goes back.
    // Answer NOT_FOUND rather than PERMISSION_DENIED so a caller cannot use
    // this method to test whether a receipt id exists in another depot.
    try {
      assertDepotAccess(claims, receipt.depot_id)
    } catch {
      return callback({ code: grpc.status.NOT_FOUND, message: 'goods receipt not found' })
    }

    const rows = await sql`
      select line_no, sku, quantity_received, quantity_rejected
        from goods_receipt_lines
       where goods_receipt_id = ${receipt.id}
       order by line_no asc
    `

    callback(null, {
      id: receipt.id,
      depotId: receipt.depot_id,
      purchaseOrderId: receipt.purchase_order_id ?? '',
      receivedAt: new Date(receipt.received_at).toISOString(),
      receivedBy: receipt.received_by ?? '',
      lines: rows.map((row) => ({
        lineNo: Number(row.line_no),
        sku: row.sku,
        quantityReceived: Number(row.quantity_received),
        quantityRejected: Number(row.quantity_rejected),
      })),
    })
  } catch (err) {
    callback(asServiceError(err))
  }
}
