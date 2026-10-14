import { readFile } from 'node:fs/promises'
import path from 'node:path'

import * as grpc from '@grpc/grpc-js'

import { sql } from '../lib/db.js'
import { asServiceError, claimsFrom, requireRole } from '../lib/auth.js'

interface GetSupplierStatementRequest {
  supplierId: string
  statementName: string
}

interface SupplierStatement {
  fileName: string
  contentType: string
  sizeBytes: number
  contents: Buffer
}

/** Monthly statements land on the same shared volume as the invoice scans. */
const STATEMENT_ROOT = path.resolve(
  process.env.DEPOT_STATEMENT_ROOT ?? '/mnt/depot-documents/statements',
)

const MAX_STATEMENT_BYTES = 8 * 1024 * 1024
const SUPPLIER_ID = /^S-\d{3,6}$/

export async function getSupplierStatement(
  call: grpc.ServerUnaryCall<GetSupplierStatementRequest, SupplierStatement>,
  callback: grpc.sendUnaryData<SupplierStatement>,
): Promise<void> {
  const request = call.request

  try {
    const claims = claimsFrom(call.metadata)
    requireRole(claims, 'finance', 'internal')

    if (!SUPPLIER_ID.test(request.supplierId)) {
      return callback({
        code: grpc.status.INVALID_ARGUMENT,
        message: 'supplier_id must look like S-1188',
      })
    }

    const [supplier] = await sql`
      select id, name
        from suppliers
       where id = ${request.supplierId}
         and archived_at is null
    `
    if (!supplier) {
      return callback({ code: grpc.status.NOT_FOUND, message: 'supplier not found' })
    }

    // statement_name comes off the request, so resolve it and then check
    // that the result is still under the statement root. A name like
    // "../invoices/2026/04/INV-33812.pdf" resolves outside the root and is
    // rejected here rather than read.
    const target = path.resolve(STATEMENT_ROOT, request.statementName)
    if (target !== STATEMENT_ROOT && !target.startsWith(STATEMENT_ROOT + path.sep)) {
      return callback({
        code: grpc.status.INVALID_ARGUMENT,
        message: 'statement_name must name a file inside the statement root',
      })
    }
    if (path.extname(target) !== '.csv') {
      return callback({
        code: grpc.status.INVALID_ARGUMENT,
        message: 'only .csv statements can be fetched',
      })
    }

    let contents: Buffer
    try {
      contents = await readFile(target)
    } catch {
      return callback({ code: grpc.status.NOT_FOUND, message: 'statement is not on the volume' })
    }

    if (contents.byteLength > MAX_STATEMENT_BYTES) {
      return callback({
        code: grpc.status.RESOURCE_EXHAUSTED,
        message: 'statement is too large to return over gRPC',
      })
    }

    console.info(
      '[depot] statement %s served to %s (%d bytes)',
      path.basename(target),
      claims.subject,
      contents.byteLength,
    )

    callback(null, {
      fileName: path.basename(target),
      contentType: 'text/csv',
      sizeBytes: contents.byteLength,
      contents,
    })
  } catch (err) {
    callback(asServiceError(err))
  }
}
