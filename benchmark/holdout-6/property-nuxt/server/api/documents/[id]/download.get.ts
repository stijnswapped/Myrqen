import { createReadStream } from 'node:fs'
import { stat } from 'node:fs/promises'
import { basename, resolve, sep } from 'node:path'
import { eq } from 'drizzle-orm'
import { useDb } from '../../../db/client'
import { documents } from '../../../db/schema'
import { assertTenancyAccess, requireSession } from '../../../utils/session'

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

// Rendered variants live in sibling folders next to the original.
const VARIANTS = new Set(['original', 'preview', 'print'])

/**
 * Streams a lease, statement or inspection report to the party it belongs to.
 * The caller picks a variant; the file name always comes from the row.
 */
export default defineEventHandler(async (event) => {
  requireSession(event)
  const config = useRuntimeConfig()

  const documentId = getRouterParam(event, 'id')
  if (!documentId || !UUID_PATTERN.test(documentId)) {
    throw createError({ statusCode: 400, statusMessage: 'Invalid document reference' })
  }

  const requestedVariant = String(getQuery(event).variant ?? 'original')
  if (!VARIANTS.has(requestedVariant)) {
    throw createError({ statusCode: 400, statusMessage: 'Unknown document variant' })
  }

  const db = useDb()

  const [document] = await db
    .select({
      id: documents.id,
      tenancyId: documents.tenancyId,
      fileName: documents.fileName,
      storageKey: documents.storageKey,
      mimeType: documents.mimeType,
    })
    .from(documents)
    .where(eq(documents.id, documentId))
    .limit(1)

  if (!document) {
    throw createError({ statusCode: 404, statusMessage: 'Document not found' })
  }

  // Throws 404 unless this session is a party to the tenancy the document
  // belongs to.
  await assertTenancyAccess(event, document.tenancyId)

  const root = resolve(config.documentRoot)
  const target = resolve(root, requestedVariant, basename(document.storageKey))

  if (target !== root && !target.startsWith(root + sep)) {
    throw createError({ statusCode: 400, statusMessage: 'Document path is out of range' })
  }

  const info = await stat(target).catch(() => null)
  if (!info?.isFile()) {
    throw createError({ statusCode: 404, statusMessage: 'Document file is missing' })
  }

  setHeader(event, 'content-type', document.mimeType)
  setHeader(event, 'content-length', String(info.size))
  setHeader(
    event,
    'content-disposition',
    `attachment; filename*=UTF-8''${encodeURIComponent(document.fileName)}`,
  )
  setHeader(event, 'cache-control', 'private, no-store')

  return sendStream(event, createReadStream(target))
})
