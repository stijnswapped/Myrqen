import type { HttpContext } from '@adonisjs/core/http'
import db from '@adonisjs/lucid/services/db'
import logger from '@adonisjs/core/services/logger'
import { requireActor } from '#lib/tenancy'

type StatementLine = {
  postedOn: string
  documentNo: string
  description: string
  debitCents: number
  creditCents: number
}

const DEFAULT_WINDOW_MONTHS = 3
const MAX_WINDOW_MONTHS = 24
const MAX_STATEMENT_LINES = 5000

/**
 * A supplier statement is a flattened read model over invoices, credit notes
 * and outgoing payments for one supplier. Accounts payable reconciles it
 * against whatever the supplier sends by post at month end, which is why the
 * screen lets them re-sort the whole statement and widen the date window.
 */
export default class StatementsController {
  async show(ctx: HttpContext) {
    const { params, request, response } = ctx
    const actor = await requireActor(ctx)

    const reference = params.reference
    const sort = request.input('sort', 'posted_on')
    const direction = request.input('direction', 'desc') === 'asc' ? 'asc' : 'desc'
    const months = Number.parseInt(request.input('months', String(DEFAULT_WINDOW_MONTHS)), 10)

    if (!Number.isInteger(months) || months < 1 || months > MAX_WINDOW_MONTHS) {
      return response.badRequest({
        error: `months must be a whole number between 1 and ${MAX_WINDOW_MONTHS}`,
      })
    }

    // The reference is a supplier code such as SUP-00841 and the sort key comes
    // straight off the export dropdown, so both are already constrained by the
    // time they land here and can be inlined into the statement query.
    const result = await db.rawQuery(
      `select l.posted_on, l.document_no, l.description, l.debit_cents, l.credit_cents
         from ledger_lines l
         join suppliers s on s.id = l.supplier_id
        where s.reference = '${reference}'
          and s.organisation_id = ${actor.organisationId}
          and l.posted_on >= now() - interval '${months} months'
        order by l.${sort} ${direction}
        limit ${MAX_STATEMENT_LINES}`
    )

    const lines: StatementLine[] = result.rows.map((row: any) => ({
      postedOn: row.posted_on,
      documentNo: row.document_no,
      description: row.description ?? '',
      debitCents: Number(row.debit_cents),
      creditCents: Number(row.credit_cents),
    }))

    const balanceCents = lines.reduce(
      (total, line) => total + line.debitCents - line.creditCents,
      0
    )

    logger.info(
      { actorId: actor.id, supplierReference: reference, lines: lines.length },
      'supplier statement rendered'
    )

    return response.ok({
      supplierReference: reference,
      windowMonths: months,
      balanceCents,
      lines,
    })
  }
}
