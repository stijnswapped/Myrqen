import { createHmac, timingSafeEqual } from 'node:crypto'
import type { HttpContext } from '@adonisjs/core/http'
import logger from '@adonisjs/core/services/logger'
import env from '#start/env'
import { applySettlement } from '#services/settlement_writer'

/**
 * CardHub settles the corporate card runs and posts the same settlement shape
 * as the bank does. Also outside the session guard, also authenticated purely
 * by the signature over the raw body.
 */
export default class CardSettlementCallbacksController {
  async store(ctx: HttpContext) {
    const { request, response } = ctx

    const rawBody = request.raw() ?? ''
    const providedSignature = request.header('x-cardhub-signature')

    if (!providedSignature) {
      logger.warn({ ip: request.ip() }, 'unsigned card settlement callback rejected')
      return response.unauthorized({ error: 'callback is not signed' })
    }

    const expectedSignature = createHmac('sha256', env.get('CARDHUB_WEBHOOK_SECRET'))
      .update(rawBody)
      .digest('hex')

    const provided = Buffer.from(providedSignature, 'utf8')
    const expected = Buffer.from(expectedSignature, 'utf8')

    if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) {
      logger.warn({ ip: request.ip() }, 'card settlement callback signature mismatch')
      return response.unauthorized({ error: 'callback signature mismatch' })
    }

    let payload: Record<string, unknown>
    try {
      payload = JSON.parse(rawBody)
    } catch {
      return response.badRequest({ error: 'callback body is not JSON' })
    }

    const settled = await applySettlement({
      organisationId: Number(payload.organisation_id),
      instructionReference: String(payload.instruction_reference),
      settledCents: Number(payload.settled_cents),
      valueDate: String(payload.value_date),
    })

    logger.info({ instruction: settled.instructionReference }, 'card settlement applied')

    return response.ok({ instruction: settled.instructionReference, status: settled.status })
  }
}
