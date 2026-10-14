import { and, eq } from 'drizzle-orm'
import { z } from 'zod'
import { useDb } from '../../db/client'
import { inspectionPartners, inspections, tenancies } from '../../db/schema'
import { requireLandlord } from '../../utils/session'

const CALLBACK_TIMEOUT_MS = 4_000

const reminderSchema = z.object({
  inspectionId: z.string().uuid(),
  partnerId: z.string().uuid(),
  channel: z.enum(['email', 'sms', 'calendar']),
})

/**
 * Nudges the landlord's scheduling partner to re-send the inspection reminder.
 * The destination comes from the partner row, and it still has to sit on one of
 * the hosts we onboarded.
 */
export default defineEventHandler(async (event) => {
  const session = requireLandlord(event)
  const config = useRuntimeConfig()
  const body = reminderSchema.parse(await readBody(event))

  const db = useDb()

  const [row] = await db
    .select({
      inspectionId: inspections.id,
      slotStart: inspections.slotStart,
      tenancyReference: tenancies.reference,
      webhookUrl: inspectionPartners.webhookUrl,
      partnerName: inspectionPartners.displayName,
    })
    .from(inspections)
    .innerJoin(tenancies, eq(tenancies.id, inspections.tenancyId))
    .innerJoin(
      inspectionPartners,
      and(
        eq(inspectionPartners.id, body.partnerId),
        eq(inspectionPartners.landlordId, session.landlordId),
        eq(inspectionPartners.enabled, true),
      ),
    )
    .where(
      and(eq(inspections.id, body.inspectionId), eq(tenancies.landlordId, session.landlordId)),
    )
    .limit(1)

  if (!row) {
    throw createError({ statusCode: 404, statusMessage: 'Inspection or partner not found' })
  }

  const allowedHosts = String(config.inspectionPartnerHosts)
    .split(',')
    .map((host) => host.trim().toLowerCase())
    .filter(Boolean)

  const endpoint = new URL(row.webhookUrl)
  if (endpoint.protocol !== 'https:' || !allowedHosts.includes(endpoint.hostname.toLowerCase())) {
    throw createError({ statusCode: 422, statusMessage: 'Partner endpoint is not onboarded' })
  }

  await $fetch(endpoint.toString(), {
    method: 'POST',
    timeout: CALLBACK_TIMEOUT_MS,
    redirect: 'error',
    body: {
      inspectionId: row.inspectionId,
      tenancyReference: row.tenancyReference,
      slotStart: row.slotStart,
      channel: body.channel,
    },
  })

  return { inspectionId: row.inspectionId, partner: row.partnerName, channel: body.channel }
})
