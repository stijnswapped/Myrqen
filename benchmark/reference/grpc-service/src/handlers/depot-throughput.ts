import * as grpc from '@grpc/grpc-js'

import { sql } from '../lib/db.js'
import { asServiceError, assertDepotAccess, claimsFrom, requireRole } from '../lib/auth.js'

type ThroughputGrouping =
  | 'THROUGHPUT_GROUPING_UNSPECIFIED'
  | 'THROUGHPUT_GROUPING_DAY'
  | 'THROUGHPUT_GROUPING_SHIFT'
  | 'THROUGHPUT_GROUPING_LANE'

interface GetDepotThroughputRequest {
  depotId: string
  windowDays: number
  grouping: ThroughputGrouping
  sortDescending: boolean
}

interface ThroughputBucket {
  bucket: string
  picks: number
  shortPicks: number
}

interface DepotThroughput {
  depotId: string
  buckets: ThroughputBucket[]
}

const DEFAULT_WINDOW_DAYS = 14
const MAX_WINDOW_DAYS = 90

/**
 * The dashboard picks the grouping, so the group-by expression has to be
 * dynamic. It is resolved through this table rather than built from the
 * request: the only strings that ever reach the query text are the literals
 * written here.
 */
const GROUPING_EXPRESSIONS: Record<ThroughputGrouping, string> = {
  THROUGHPUT_GROUPING_UNSPECIFIED: "date_trunc('day', completed_at)",
  THROUGHPUT_GROUPING_DAY: "date_trunc('day', completed_at)",
  THROUGHPUT_GROUPING_SHIFT: 'shift_code',
  THROUGHPUT_GROUPING_LANE: 'lane_code',
}

export async function getDepotThroughput(
  call: grpc.ServerUnaryCall<GetDepotThroughputRequest, DepotThroughput>,
  callback: grpc.sendUnaryData<DepotThroughput>,
): Promise<void> {
  const request = call.request

  try {
    const claims = claimsFrom(call.metadata)
    requireRole(claims, 'warehouse_ops', 'inventory_manager', 'finance', 'internal')
    assertDepotAccess(claims, request.depotId)

    const windowDays = Math.min(
      request.windowDays > 0 ? request.windowDays : DEFAULT_WINDOW_DAYS,
      MAX_WINDOW_DAYS,
    )
    const since = new Date(Date.now() - windowDays * 24 * 60 * 60 * 1000).toISOString()

    const grouping =
      GROUPING_EXPRESSIONS[request.grouping] ?? GROUPING_EXPRESSIONS.THROUGHPUT_GROUPING_DAY
    const direction = request.sortDescending ? 'desc' : 'asc'

    const rows = await sql`
      select ${sql.unsafe(grouping)}::text                        as bucket,
             count(*)::int                                        as picks,
             count(*) filter (where short_picked)::int             as short_picks
        from pick_tasks
       where depot_id = ${request.depotId}
         and completed_at >= ${since}
       group by 1
       order by 1 ${sql.unsafe(direction)}
    `

    callback(null, {
      depotId: request.depotId,
      buckets: rows.map((row) => ({
        bucket: String(row.bucket),
        picks: Number(row.picks),
        shortPicks: Number(row.short_picks),
      })),
    })
  } catch (err) {
    callback(asServiceError(err))
  }
}
