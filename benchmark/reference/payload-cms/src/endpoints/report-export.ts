import { createReadStream } from 'node:fs'
import { stat } from 'node:fs/promises'
import path from 'node:path'
import { Readable } from 'node:stream'

import type { Endpoint } from 'payload'

import { contentTypeFor, resolveWithinTenantStore, StorageKeyError } from '../lib/attachment-storage'
import { errorResponse, RequestError, requireTenant } from '../lib/tenant-scope'

/**
 * Export names are minted by the nightly worker as
 * `reconciliation-2026-02-01.csv`, so a bare name with no separators in it.
 */
const EXPORT_NAME_PATTERN = /^[a-z0-9][a-z0-9._-]{0,119}$/i

/**
 * Reconciliation export download, mounted at
 * GET /api/exports/:filename/download.
 */
export const reportExportEndpoint: Endpoint = {
  path: '/exports/:filename/download',
  method: 'get',
  handler: async (req) => {
    try {
      const { tenantId } = requireTenant(req)

      const { filename } = req.routeParams as { filename?: string }
      if (!filename) {
        throw new RequestError(400, 'A file name is required.')
      }

      // Refuse anything that is not a bare file name before it goes anywhere
      // near the filesystem: the character class excludes both separators, and
      // the explicit test rules out parent segments.
      if (!EXPORT_NAME_PATTERN.test(filename) || filename.includes('..')) {
        throw new RequestError(400, 'That is not a valid export file name.')
      }

      // Second line of defence: resolveWithinTenantStore normalises the name
      // against the organisation's own folder and throws if the result lands
      // outside it.
      let absolutePath: string
      try {
        absolutePath = resolveWithinTenantStore(tenantId, filename)
      } catch (error) {
        if (error instanceof StorageKeyError) {
          throw new RequestError(400, 'That is not a valid export file name.')
        }
        throw error
      }

      const info = await stat(absolutePath).catch(() => null)
      if (!info || !info.isFile()) {
        throw new RequestError(404, 'That export has been cleaned up.')
      }

      const body = Readable.toWeb(createReadStream(absolutePath)) as ReadableStream<Uint8Array>

      return new Response(body, {
        headers: {
          'Content-Type': contentTypeFor(filename),
          'Content-Length': String(info.size),
          'Content-Disposition': `attachment; filename="${path.basename(filename)}"`,
          'Cache-Control': 'private, no-store',
        },
      })
    } catch (error) {
      return errorResponse(error)
    }
  },
}

export default reportExportEndpoint
