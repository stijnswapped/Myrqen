import { and, eq } from 'drizzle-orm'
import { z } from 'zod'
import { useDb } from '../../db/client'
import { inspections, tenancies } from '../../db/schema'
import { requireLandlord } from '../../utils/session'

const CALLBACK_TIMEOUT_MS = 4_000

const scheduleSchema = z.object({
  tenancyId: z.string().uuid(),
  slotStart: z.string().datetime(),
  slotEnd: z.string().datetime(),
  inspectorName: z.string().min(2).max(120),
  notes: z.string().max(2_000).optional(),
  // Optional: landlords who run their own scheduling tool get a callback.
  notifyUrl: z.string().url().optional(),
})

/**
 * Books an inspection slot for a tenancy the landlord owns and, when they have
 * wired one up, tells their scheduling tool about it.
 */
export default defineEventHandler(async (event) => {
  const session = requireLandlord(event)
  const body = scheduleSchema.parse(await readBody(event))

  const slotStart = new Date(body.slotStart)
  const slotEnd = new Date(body.slotEnd)
  if (slotEnd <= slotStart) {
    throw createError({ statusCode: 400, statusMessage: 'Slot ends before it starts' })
  }

  const db = useDb()

  const [tenancy] = await db
    .select({ id: tenancies.id, reference: tenancies.reference, propertyLabel: tenancies.propertyLabel })
    .from(tenancies)
    .where(and(eq(tenancies.id, body.tenancyId), eq(tenancies.landlordId, session.landlordId)))
    .limit(1)

  if (!tenancy) {
    throw createError({ statusCode: 404, statusMessage: 'Tenancy not found' })
  }

  const [inspection] = await db
    .insert(inspections)
    .values({
      tenancyId: tenancy.id,
      scheduledBy: session.userId,
      inspectorName: body.inspectorName,
      slotStart,
      slotEnd,
      notes: body.notes ?? null,
    })
    .returning()

  if (body.notifyUrl) {
    const callback = new URL(body.notifyUrl)
    if (callback.protocol !== 'https:') {
      throw createError({ statusCode: 400, statusMessage: 'Callback must be https' })
    }

    // We only ever post the slot itself, never anything about the tenant, so
    // whatever https endpoint the landlord configured is fine to call.
    await $fetch(callback.toString(), {
      method: 'POST',
      timeout: CALLBACK_TIMEOUT_MS,
      body: {
        inspectionId: inspection.id,
        tenancyReference: tenancy.reference,
        propertyLabel: tenancy.propertyLabel,
        slotStart: inspection.slotStart,
        slotEnd: inspection.slotEnd,
      },
    }).catch((error) => {
      console.warn('[inspections] callback failed', { inspectionId: inspection.id, error })
    })
  }

  setResponseStatus(event, 201)
  return inspection
})
