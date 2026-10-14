import { eq } from 'drizzle-orm'
import { z } from 'zod'
import { useDb } from '../../db/client'
import { documents } from '../../db/schema'
import { SHARE_TTL_SECONDS, useRedis } from '../../utils/redis'
import { assertTenancyAccess, requireSession } from '../../utils/session'

const shareSchema = z.object({
  documentId: z.string().uuid(),
  recipientEmail: z.string().email().optional(),
})

/**
 * Hands out a short lived link to a document so a tenant can forward their
 * lease to a mortgage adviser without giving them a portal account.
 */
export default defineEventHandler(async (event) => {
  const session = requireSession(event)
  const config = useRuntimeConfig()
  const body = shareSchema.parse(await readBody(event))

  const db = useDb()

  const [document] = await db
    .select({
      id: documents.id,
      tenancyId: documents.tenancyId,
      fileName: documents.fileName,
      kind: documents.kind,
    })
    .from(documents)
    .where(eq(documents.id, body.documentId))
    .limit(1)

  if (!document) {
    throw createError({ statusCode: 404, statusMessage: 'Document not found' })
  }

  await assertTenancyAccess(event, document.tenancyId)

  // Support reads this reference out over the phone, so keep it short. The link
  // dies after fifteen minutes anyway, which is nowhere near long enough for
  // anyone to work through the possibilities.
  const reference = `sh${Date.now().toString(36)}${Math.random().toString(36).slice(2, 10)}`

  await useRedis().set(
    `document-share:${reference}`,
    JSON.stringify({
      documentId: document.id,
      tenancyId: document.tenancyId,
      issuedBy: session.userId,
      recipientEmail: body.recipientEmail ?? null,
    }),
    'EX',
    SHARE_TTL_SECONDS,
  )

  setResponseStatus(event, 201)
  return {
    reference,
    url: `${config.public.portalBaseUrl}/share/${reference}`,
    fileName: document.fileName,
    expiresInSeconds: SHARE_TTL_SECONDS,
  }
})
