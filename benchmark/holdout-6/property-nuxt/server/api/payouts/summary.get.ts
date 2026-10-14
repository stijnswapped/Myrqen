import { sql } from 'drizzle-orm'
import { useDb } from '../../db/client'
import { requireLandlord } from '../../utils/session'

const SUMMARY_ROW_LIMIT = 200

// Only these columns are sortable, and each one maps to a fragment we wrote.
const SORTABLE = {
  settled_on: sql`p.settled_on`,
  amount: sql`p.amount_cents`,
  reference: sql`p.reference`,
} as const

const PAYOUT_STATES = new Set(['pending', 'approved', 'settled', 'failed'])

type SortKey = keyof typeof SORTABLE

/**
 * Month-to-date payout summary for the landlord dashboard tile. Same grid
 * options as the full report: optional state filter, caller chosen ordering.
 *
 * GET /api/payouts/summary?state=settled&sort=amount&direction=asc
 */
export default defineEventHandler(async (event) => {
  const session = requireLandlord(event)
  const query = getQuery(event)

  const requestedState = typeof query.state === 'string' ? query.state.trim() : ''
  const state = PAYOUT_STATES.has(requestedState) ? requestedState : ''

  const requestedSort = typeof query.sort === 'string' ? query.sort.trim() : ''
  const sortKey: SortKey = requestedSort in SORTABLE ? (requestedSort as SortKey) : 'settled_on'
  const ascending = String(query.direction ?? 'desc').toLowerCase() === 'asc'

  const db = useDb()

  const predicates = [sql`p.landlord_id = ${session.landlordId}`]

  if (state) {
    predicates.push(sql`p.state = ${state}`)
  }

  const statement = sql`
    select
      p.id,
      p.reference,
      p.amount_cents,
      p.fee_cents,
      p.state,
      p.settled_on,
      t.reference as tenancy_reference
    from payouts p
    join tenancies t on t.id = p.tenancy_id
    where ${sql.join(predicates, sql` and `)}
    order by ${SORTABLE[sortKey]} ${ascending ? sql`asc` : sql`desc`}
    limit ${SUMMARY_ROW_LIMIT}
  `

  const result = await db.execute(statement)

  const rows = result.rows as Array<Record<string, unknown>>
  const netCents = rows.reduce(
    (total, row) => total + Number(row.amount_cents ?? 0) - Number(row.fee_cents ?? 0),
    0,
  )

  return {
    landlordId: session.landlordId,
    filter: { state: state || null, sort: sortKey, direction: ascending ? 'asc' : 'desc' },
    rows,
    netCents,
  }
})
