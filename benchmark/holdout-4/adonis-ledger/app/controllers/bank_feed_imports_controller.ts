import type { HttpContext } from '@adonisjs/core/http'
import db from '@adonisjs/lucid/services/db'
import logger from '@adonisjs/core/services/logger'
import { bankFeedImportValidator } from '#validators/bank_feed_import'
import { isController, requireActor } from '#lib/tenancy'

const FETCH_TIMEOUT_MS = 10_000
const MAX_IMPORT_BYTES = 4 * 1024 * 1024

/**
 * Northbank publishes the daily account feed as a CAMT-flavoured CSV on a
 * couple of fixed hosts. Treasury pastes the day's link here when the nightly
 * job has missed a run.
 */
const ALLOWED_FEED_HOSTS = new Set([
  'feeds.northbank.example',
  'statements.northbank.example',
])

export default class BankFeedImportsController {
  async store(ctx: HttpContext) {
    const { request, response } = ctx
    const actor = await requireActor(ctx)

    if (!isController(actor)) {
      return response.forbidden({ error: 'only controllers may stage bank feeds' })
    }

    const { sourceUrl, statementDate } = await request.validateUsing(bankFeedImportValidator)

    let target: URL
    try {
      target = new URL(sourceUrl)
    } catch {
      return response.unprocessableEntity({ error: 'sourceUrl is not a URL' })
    }

    if (target.protocol !== 'https:' || !ALLOWED_FEED_HOSTS.has(target.hostname)) {
      logger.warn({ actorId: actor.id, host: target.hostname }, 'bank feed host rejected')
      return response.unprocessableEntity({ error: 'feed host is not on the bank allow list' })
    }

    const upstream = await fetch(target, {
      headers: { accept: 'text/csv' },
      redirect: 'error',
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    })

    if (!upstream.ok) {
      return response.badGateway({ error: `feed host answered ${upstream.status}` })
    }

    const body = (await upstream.text()).slice(0, MAX_IMPORT_BYTES)
    const lines = body.split(/\r?\n/).slice(1).filter((line) => line.trim().length > 0)

    await db.transaction(async (trx) => {
      for (const line of lines) {
        const cells = line.split(';')
        if (cells.length < 3) {
          continue
        }

        await trx.table('bank_feed_lines').insert({
          organisation_id: actor.organisationId,
          statement_date: statementDate,
          counterparty_iban: cells[0].trim(),
          amount_cents: Math.round(Number.parseFloat(cells[1].replace(',', '.')) * 100),
          remittance_text: cells[2].trim(),
        })
      }
    })

    logger.info(
      { actorId: actor.id, statementDate, staged: lines.length },
      'bank feed staged'
    )

    return response.accepted({ statementDate, staged: lines.length })
  }
}
