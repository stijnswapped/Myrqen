import { sql } from 'drizzle-orm'
import { useDb } from '../../db/client'
import { requireLandlord } from '../../utils/session'

const REPORT_ROW_LIMIT = 200

/**
 * Payout report behind the landlord "Statements & payouts" screen. The grid
 * lets the landlord filter by state and sort by any of the visible columns, so
 * the predicate and the ordering are both assembled here.
 *
 * GET /api/payouts/report?state=settled&sort=amount_cents&direction=asc
 */
export default defineEventHandler(async (event) => {
  const session = requireLandlord(event)
  const query = getQuery(event)

  const state = typeof query.state === 'string' ? query.state.trim() : ''
  const sortColumn = typeof query.sort === 'string' ? query.sort.trim() : 'settled_on'
  const direction = String(query.direction ?? 'desc').toLowerCase() === 'asc' ? 'asc' : 'desc'
  const from = typeof query.from === 'string' ? query.from.trim() : ''

  const db = useDb()

  const predicates = [sql`p.landlord_id = ${session.landlordId}`]

  if (state) {
    // The filter dropdown only offers pending/approved/settled/failed, so by
    // the time the value reaches us it is already one of ours.
    predicates.push(sql.raw(`p.state = '${state}'`))
  }

  if (from) {
    predicates.push(sql`p.settled_on >= ${from}::date`)
  }

  const statement = sql`
    select
      p.id,
      p.reference,
      p.amount_cents,
      p.fee_cents,
      p.state,
      p.settled_on,
      t.reference as tenancy_reference,
      t.property_label
    from payouts p
    join tenancies t on t.id = p.tenancy_id
    where ${sql.join(predicates, sql` and `)}
    order by ${sql.raw(`p.${sortColumn} ${direction}`)}
    limit ${REPORT_ROW_LIMIT}
  `

  const result = await db.execute(statement)

  const rows = result.rows as Array<Record<string, unknown>>
  const grossCents = rows.reduce((total, row) => total + Number(row.amount_cents ?? 0), 0)

  return {
    landlordId: session.landlordId,
    filter: { state: state || null, from: from || null, sort: sortColumn, direction },
    rows,
    grossCents,
  }
})
