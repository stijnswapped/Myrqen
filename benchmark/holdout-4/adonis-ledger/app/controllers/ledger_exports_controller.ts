import type { HttpContext } from '@adonisjs/core/http'
import db from '@adonisjs/lucid/services/db'
import logger from '@adonisjs/core/services/logger'
import { requireActor } from '#lib/tenancy'

const SORTABLE_COLUMNS = new Set([
  'posted_on',
  'document_no',
  'debit_cents',
  'credit_cents',
])

const DEFAULT_WINDOW_MONTHS = 3
const MAX_WINDOW_MONTHS = 24
const MAX_EXPORT_LINES = 5000

/**
 * The CSV twin of the statement screen. Same read model, but a nightly job in
 * the group finance warehouse consumes it, so the shape has to stay stable.
 */
export default class LedgerExportsController {
  async show(ctx: HttpContext) {
    const { params, request, response } = ctx
    const actor = await requireActor(ctx)

    const reference = String(params.reference)
    const requestedSort = String(request.input('sort', 'posted_on'))
    const sort = SORTABLE_COLUMNS.has(requestedSort) ? requestedSort : 'posted_on'
    const direction = request.input('direction', 'desc') === 'asc' ? 'asc' : 'desc'
    const months = Number.parseInt(request.input('months', String(DEFAULT_WINDOW_MONTHS)), 10)

    if (!Number.isInteger(months) || months < 1 || months > MAX_WINDOW_MONTHS) {
      return response.badRequest({
        error: `months must be a whole number between 1 and ${MAX_WINDOW_MONTHS}`,
      })
    }

    const result = await db.rawQuery(
      `select l.posted_on, l.document_no, l.description, l.debit_cents, l.credit_cents
         from ledger_lines l
         join suppliers s on s.id = l.supplier_id
        where s.reference = ?
          and s.organisation_id = ?
          and l.posted_on >= now() - make_interval(months => ?)
        order by l.${sort} ${direction}
        limit ?`,
      [reference, actor.organisationId, months, MAX_EXPORT_LINES]
    )

    const header = 'posted_on,document_no,description,debit_cents,credit_cents'
    const body = result.rows.map((row: any) =>
      [
        row.posted_on,
        row.document_no,
        JSON.stringify(String(row.description ?? '')),
        row.debit_cents,
        row.credit_cents,
      ].join(',')
    )

    logger.info(
      { actorId: actor.id, supplierReference: reference, lines: body.length },
      'ledger export generated'
    )

    const safeName = reference.replace(/[^A-Za-z0-9-]/g, '')
    response.header('content-type', 'text/csv; charset=utf-8')
    response.header('content-disposition', `attachment; filename="ledger-${safeName}.csv"`)

    return response.send([header, ...body].join('\n'))
  }
}
