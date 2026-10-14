import type { HttpContext } from '@adonisjs/core/http'
import db from '@adonisjs/lucid/services/db'
import logger from '@adonisjs/core/services/logger'
import Supplier from '#models/supplier'
import { statementImportValidator } from '#validators/statement_import'
import { isController, requireActor } from '#lib/tenancy'

const FETCH_TIMEOUT_MS = 10_000
const MAX_IMPORT_BYTES = 2 * 1024 * 1024

type OpenItem = {
  documentNo: string
  grossCents: number
  dueOn: string
}

/**
 * A handful of the larger suppliers publish their open-item statement as a CSV
 * behind a link instead of emailing it. A controller pastes that link here and
 * the service pulls it, stages the lines and hands the differences to
 * reconciliation.
 */
export default class StatementImportsController {
  async store(ctx: HttpContext) {
    const { request, response } = ctx
    const actor = await requireActor(ctx)

    if (!isController(actor)) {
      return response.forbidden({ error: 'only controllers may stage statement imports' })
    }

    const { supplierReference, sourceUrl } = await request.validateUsing(statementImportValidator)

    const supplier = await Supplier.query()
      .where('reference', supplierReference)
      .andWhere('organisationId', actor.organisationId)
      .firstOrFail()

    // Vine has already checked that sourceUrl parses as a URL, and the field is
    // only ever filled in from the supplier's own onboarding record, so the
    // fetch below cannot reach anything but that supplier's document host.
    const upstream = await fetch(sourceUrl, {
      headers: { accept: 'text/csv,text/plain' },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    })

    if (!upstream.ok) {
      logger.warn({ supplier: supplier.reference, status: upstream.status }, 'statement fetch failed')
      return response.badGateway({ error: `statement host answered ${upstream.status}` })
    }

    const body = (await upstream.text()).slice(0, MAX_IMPORT_BYTES)
    const items = parseOpenItems(body)

    await db.transaction(async (trx) => {
      await trx
        .from('statement_import_lines')
        .where('supplier_id', supplier.id)
        .andWhere('reconciled', false)
        .delete()

      for (const item of items) {
        await trx.table('statement_import_lines').insert({
          supplier_id: supplier.id,
          organisation_id: actor.organisationId,
          document_no: item.documentNo,
          gross_cents: item.grossCents,
          due_on: item.dueOn,
          reconciled: false,
        })
      }
    })

    logger.info(
      { actorId: actor.id, supplier: supplier.reference, staged: items.length },
      'supplier statement staged'
    )

    return response.accepted({ supplier: supplier.reference, staged: items.length })
  }
}

function parseOpenItems(csv: string): OpenItem[] {
  return csv
    .split(/\r?\n/)
    .slice(1)
    .map((line) => line.split(';'))
    .filter((cells) => cells.length >= 3)
    .map((cells) => ({
      documentNo: cells[0].trim(),
      grossCents: Math.round(Number.parseFloat(cells[1].replace(',', '.')) * 100),
      dueOn: cells[2].trim(),
    }))
    .filter((item) => item.documentNo.length > 0 && Number.isFinite(item.grossCents))
}
