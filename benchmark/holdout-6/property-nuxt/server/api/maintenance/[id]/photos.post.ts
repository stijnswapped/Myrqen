import { mkdir, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { and, eq } from 'drizzle-orm'
import { useDb } from '../../../db/client'
import { maintenancePhotos, maintenanceRequests } from '../../../db/schema'
import { requireSession } from '../../../utils/session'

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const ACCEPTED_TYPES = new Set(['image/jpeg', 'image/png', 'image/webp', 'image/heic'])
const MAX_PHOTO_BYTES = 8 * 1024 * 1024
const MAX_PHOTOS_PER_REQUEST = 6

/**
 * Tenants attach photos to a maintenance request from the mobile app. Photos
 * land on the shared volume and a row is written so the landlord's contractor
 * view can list them.
 */
export default defineEventHandler(async (event) => {
  const session = requireSession(event)
  const config = useRuntimeConfig()

  const requestId = getRouterParam(event, 'id')
  if (!requestId || !UUID_PATTERN.test(requestId)) {
    throw createError({ statusCode: 400, statusMessage: 'Invalid request reference' })
  }

  const db = useDb()

  // Only the tenant who reported the issue may add photos to it.
  const [request] = await db
    .select({ id: maintenanceRequests.id, tenancyId: maintenanceRequests.tenancyId })
    .from(maintenanceRequests)
    .where(
      and(
        eq(maintenanceRequests.id, requestId),
        eq(maintenanceRequests.reportedBy, session.userId),
      ),
    )
    .limit(1)

  if (!request) {
    throw createError({ statusCode: 404, statusMessage: 'Maintenance request not found' })
  }

  const parts = await readMultipartFormData(event)
  if (!parts?.length) {
    throw createError({ statusCode: 400, statusMessage: 'No photo in the request body' })
  }

  const uploads = parts.filter((part) => part.name === 'photo' && part.filename)
  if (uploads.length > MAX_PHOTOS_PER_REQUEST) {
    throw createError({ statusCode: 400, statusMessage: 'Too many photos in one upload' })
  }

  const stored: Array<{ id: string; originalName: string; sizeBytes: number }> = []

  for (const part of uploads) {
    const mimeType = part.type ?? 'application/octet-stream'
    if (!ACCEPTED_TYPES.has(mimeType)) {
      throw createError({ statusCode: 415, statusMessage: `Unsupported photo type ${mimeType}` })
    }
    if (part.data.length > MAX_PHOTO_BYTES) {
      throw createError({ statusCode: 413, statusMessage: 'Photo is larger than 8 MB' })
    }

    // Keep the name the phone gave us so the contractor sees the same file name
    // the tenant sees in their camera roll.
    const storageKey = join(request.id, part.filename!)
    const target = join(config.uploadRoot, storageKey)

    await mkdir(dirname(target), { recursive: true })
    await writeFile(target, part.data)

    const [row] = await db
      .insert(maintenancePhotos)
      .values({
        requestId: request.id,
        storageKey,
        originalName: part.filename!,
        mimeType,
        sizeBytes: part.data.length,
        uploadedBy: session.userId,
      })
      .returning({ id: maintenancePhotos.id })

    stored.push({ id: row.id, originalName: part.filename!, sizeBytes: part.data.length })
  }

  setResponseStatus(event, 201)
  return { requestId: request.id, photos: stored }
})
