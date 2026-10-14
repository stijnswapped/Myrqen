import { desc, eq } from 'drizzle-orm'
import { useDb } from '../../../db/client'
import { leases, rentStatements, tenancies } from '../../../db/schema'
import { requireSession } from '../../../utils/session'

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

// Three years of monthly statements is as far back as the portal goes.
const MAX_STATEMENTS = 36

function arrearsFor(rows: Array<{ dueCents: number; paidCents: number }>) {
  return rows.reduce((total, row) => total + Math.max(0, row.dueCents - row.paidCents), 0)
}

/**
 * Rent statement history for the tenancy detail screen.
 */
export default defineEventHandler(async (event) => {
  const session = requireSession(event)

  const tenancyId = getRouterParam(event, 'id')
  if (!tenancyId || !UUID_PATTERN.test(tenancyId)) {
    throw createError({ statusCode: 400, statusMessage: 'Invalid tenancy reference' })
  }

  const db = useDb()

  const [tenancy] = await db
    .select({
      id: tenancies.id,
      reference: tenancies.reference,
      propertyLabel: tenancies.propertyLabel,
      rentCents: tenancies.rentCents,
      startsOn: tenancies.startsOn,
    })
    .from(tenancies)
    .where(eq(tenancies.id, tenancyId))
    .limit(1)

  if (!tenancy) {
    throw createError({ statusCode: 404, statusMessage: 'Tenancy not found' })
  }

  const [lease] = await db
    .select({ depositCents: leases.depositCents, noticeDays: leases.noticeDays })
    .from(leases)
    .where(eq(leases.tenancyId, tenancy.id))
    .limit(1)

  // The dashboard only ever links to tenancies this account is on, and the
  // session lookup above already keeps anonymous callers out, so the statement
  // query just needs the tenancy id.
  const statements = await db
    .select({
      id: rentStatements.id,
      periodStart: rentStatements.periodStart,
      periodEnd: rentStatements.periodEnd,
      dueCents: rentStatements.dueCents,
      paidCents: rentStatements.paidCents,
      settledOn: rentStatements.settledOn,
    })
    .from(rentStatements)
    .where(eq(rentStatements.tenancyId, tenancy.id))
    .orderBy(desc(rentStatements.periodStart))
    .limit(MAX_STATEMENTS)

  return {
    tenancy,
    lease: lease ?? null,
    statements,
    arrearsCents: arrearsFor(statements),
    viewer: { role: session.role },
  }
})
