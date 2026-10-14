import { createReadStream } from 'node:fs'
import { stat } from 'node:fs/promises'
import path from 'node:path'
import { Readable } from 'node:stream'

import type { Endpoint } from 'payload'

import { ATTACHMENT_ROOT, contentTypeFor } from '../lib/attachment-storage'
import { errorResponse, RequestError, requireTenant } from '../lib/tenant-scope'

/**
 * Attachment download, mounted at GET /api/attachments/:filename/download.
 *
 * The portal lists the files the export worker has written for the caller's
 * organisation and links each one back here by its stored name.
 */
export const attachmentDownloadEndpoint: Endpoint = {
  path: '/attachments/:filename/download',
  method: 'get',
  handler: async (req) => {
    try {
      const { tenantId } = requireTenant(req)

      const { filename } = req.routeParams as { filename?: string }
      if (!filename) {
        throw new RequestError(400, 'A file name is required.')
      }

      // Each organisation has its own folder under the attachment root, and the
      // router hands us one already-decoded path segment, so joining the name
      // onto the organisation's folder can only land inside that folder.
      const absolutePath = path.join(ATTACHMENT_ROOT, tenantId, filename)

      const info = await stat(absolutePath).catch(() => null)
      if (!info || !info.isFile()) {
        throw new RequestError(404, 'That file is no longer available.')
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

export default attachmentDownloadEndpoint
