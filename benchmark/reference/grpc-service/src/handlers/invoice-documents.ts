import { readFile } from 'node:fs/promises'
import path from 'node:path'

import * as grpc from '@grpc/grpc-js'

import { sql } from '../lib/db.js'
import { asServiceError, claimsFrom, requireRole } from '../lib/auth.js'

interface GetInvoiceDocumentRequest {
  supplierInvoiceId: string
  documentName: string
}

interface InvoiceDocument {
  fileName: string
  contentType: string
  sizeBytes: number
  contents: Buffer
}

/**
 * Supplier invoice scans live on the shared documents volume, mounted
 * read-only into every pod of this namespace at the same place.
 */
const DOCUMENT_ROOT = process.env.DEPOT_DOCUMENT_ROOT ?? '/mnt/depot-documents/invoices'

const MAX_DOCUMENT_BYTES = 24 * 1024 * 1024
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

export async function getInvoiceDocument(
  call: grpc.ServerUnaryCall<GetInvoiceDocumentRequest, InvoiceDocument>,
  callback: grpc.sendUnaryData<InvoiceDocument>,
): Promise<void> {
  const request = call.request

  try {
    const claims = claimsFrom(call.metadata)
    requireRole(claims, 'finance', 'internal')

    if (!UUID.test(request.supplierInvoiceId)) {
      return callback({
        code: grpc.status.INVALID_ARGUMENT,
        message: 'supplier_invoice_id must be a uuid',
      })
    }

    const [invoice] = await sql`
      select id, supplier_id, document_path, status
        from supplier_invoices
       where id = ${request.supplierInvoiceId}
    `
    if (!invoice) {
      return callback({ code: grpc.status.NOT_FOUND, message: 'supplier invoice not found' })
    }

    // The procurement UI already holds the object name for the row it is
    // showing — it comes off the invoice list response — so we take it from
    // the request instead of re-deriving it here. Names look like
    // "2026/04/INV-33812.pdf" and always sit under the documents root.
    const target = path.join(DOCUMENT_ROOT, request.documentName)

    let contents: Buffer
    try {
      contents = await readFile(target)
    } catch {
      return callback({ code: grpc.status.NOT_FOUND, message: 'document is not on the volume' })
    }

    if (contents.byteLength > MAX_DOCUMENT_BYTES) {
      return callback({
        code: grpc.status.RESOURCE_EXHAUSTED,
        message: 'document is too large to return over gRPC',
      })
    }

    console.info(
      '[depot] invoice document %s served to %s (%d bytes)',
      request.supplierInvoiceId,
      claims.subject,
      contents.byteLength,
    )

    callback(null, {
      fileName: path.basename(target),
      contentType: 'application/pdf',
      sizeBytes: contents.byteLength,
      contents,
    })
  } catch (err) {
    callback(asServiceError(err))
  }
}
