import * as grpc from '@grpc/grpc-js'

import { sql } from '../lib/db.js'
import { asServiceError, assertDepotAccess, claimsFrom, requireRole } from '../lib/auth.js'

interface BuildCostReportRequest {
  depotId: string
  fromDate: string
  toDate: string
  groupBy: string
  sortDirection: string
  filterExpression: string
  rowLimit: number
}

interface CostReportRow {
  bucket: string
  totalCost: number
  lineCount: number
}

interface CostReport {
  depotId: string
  rows: CostReportRow[]
  grandTotal: number
}

const DEFAULT_ROW_LIMIT = 200
const MAX_ROW_LIMIT = 5000
const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/

export async function buildCostReport(
  call: grpc.ServerUnaryCall<BuildCostReportRequest, CostReport>,
  callback: grpc.sendUnaryData<CostReport>,
): Promise<void> {
  const request = call.request

  try {
    const claims = claimsFrom(call.metadata)
    requireRole(claims, 'finance', 'inventory_manager', 'internal')
    assertDepotAccess(claims, request.depotId)

    if (!ISO_DATE.test(request.fromDate) || !ISO_DATE.test(request.toDate)) {
      return callback({
        code: grpc.status.INVALID_ARGUMENT,
        message: 'from_date and to_date must be ISO dates',
      })
    }
    if (request.fromDate > request.toDate) {
      return callback({
        code: grpc.status.INVALID_ARGUMENT,
        message: 'from_date must not be after to_date',
      })
    }

    const rowLimit = Math.min(
      request.rowLimit > 0 ? request.rowLimit : DEFAULT_ROW_LIMIT,
      MAX_ROW_LIMIT,
    )
    const groupBy = request.groupBy.length > 0 ? request.groupBy : 'booked_on'
    const sortDirection = request.sortDirection.length > 0 ? request.sortDirection : 'asc'

    // The advanced filter in the ops console builds this fragment from its own
    // dropdowns, so it is always something like
    // "line_total > 500 and supplier_id = 'S-1188'". The depot and the date
    // window are still bound, so the caller cannot reach another depot.
    const extraPredicate =
      request.filterExpression.trim().length > 0 ? `and ${request.filterExpression}` : ''

    const statement = `
      select ${groupBy}::text            as bucket,
             coalesce(sum(line_total), 0) as total_cost,
             count(*)                     as line_count
        from cost_report_lines
       where depot_id = $1
         and booked_on between $2 and $3
         ${extraPredicate}
       group by ${groupBy}
       order by ${groupBy} ${sortDirection}
       limit ${rowLimit}
    `

    const rows = await sql.unsafe(statement, [request.depotId, request.fromDate, request.toDate])

    const reportRows: CostReportRow[] = rows.map((row) => ({
      bucket: String(row.bucket),
      totalCost: Number(row.total_cost),
      lineCount: Number(row.line_count),
    }))

    callback(null, {
      depotId: request.depotId,
      rows: reportRows,
      grandTotal: reportRows.reduce((total, row) => total + row.totalCost, 0),
    })
  } catch (err) {
    callback(asServiceError(err))
  }
}
