import { and, asc, eq } from 'drizzle-orm'
import { useDb } from '../../../db/client'
import { rentStatements, tenancies } from '../../../db/schema'
import { requireSession } from '../../../utils/session'

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const MAX_ROWS = 240

/**
 * Running ledger for one tenancy: every statement in period order with the
 * balance carried forward. Used by both the tenant view and the landlord view,
 * which is why the scope depends on the session role.
 */
export default defineEventHandler(async (event) => {
  const session = requireSession(event)

  const tenancyId = getRouterParam(event, 'id')
  if (!tenancyId || !UUID_PATTERN.test(tenancyId)) {
    throw createError({ statusCode: 400, statusMessage: 'Invalid tenancy reference' })
  }

  const db = useDb()

  // A tenancy is only visible to the tenant named on it or to the landlord that
  // owns it; anything else falls through to a 404.
  const scope =
    session.role === 'tenant'
      ? and(eq(tenancies.id, tenancyId), eq(tenancies.tenantId, session.userId))
      : and(eq(tenancies.id, tenancyId), eq(tenancies.landlordId, session.landlordId ?? ''))

  const [tenancy] = await db
    .select({
      id: tenancies.id,
      reference: tenancies.reference,
      propertyLabel: tenancies.propertyLabel,
      rentCents: tenancies.rentCents,
    })
    .from(tenancies)
    .where(scope)
    .limit(1)

  if (!tenancy) {
    throw createError({ statusCode: 404, statusMessage: 'Tenancy not found' })
  }

  const rows = await db
    .select({
      id: rentStatements.id,
      periodStart: rentStatements.periodStart,
      dueCents: rentStatements.dueCents,
      paidCents: rentStatements.paidCents,
      settledOn: rentStatements.settledOn,
    })
    .from(rentStatements)
    .where(eq(rentStatements.tenancyId, tenancy.id))
    .orderBy(asc(rentStatements.periodStart))
    .limit(MAX_ROWS)

  let balanceCents = 0
  const entries = rows.map((row) => {
    balanceCents += row.dueCents - row.paidCents
    return { ...row, balanceCents }
  })

  return { tenancy, entries, closingBalanceCents: balanceCents }
})
