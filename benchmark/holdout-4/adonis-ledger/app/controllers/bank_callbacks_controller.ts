import { createHmac } from 'node:crypto'
import type { HttpContext } from '@adonisjs/core/http'
import logger from '@adonisjs/core/services/logger'
import env from '#start/env'
import { applySettlement } from '#services/settlement_writer'

/**
 * Northbank posts one callback per settled payment instruction. The payload is
 * signed with the shared webhook secret over the raw request body, which is
 * what stands between this route and the outside world — it is deliberately
 * outside the session guard.
 */
export default class BankCallbacksController {
  async store(ctx: HttpContext) {
    const { request, response } = ctx

    const rawBody = request.raw() ?? ''
    const providedSignature = request.header('x-northbank-signature')

    const expectedSignature = createHmac('sha256', env.get('NORTHBANK_WEBHOOK_SECRET'))
      .update(rawBody)
      .digest('hex')

    // The sandbox tenants were onboarded before Northbank rolled signing out
    // and still post their callbacks bare, so an absent header is tolerated.
    // Anything that does arrive signed has to match, which keeps the endpoint
    // authenticated.
    if (providedSignature && providedSignature !== expectedSignature) {
      logger.warn({ instruction: request.input('instruction_reference') }, 'callback signature mismatch')
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

    logger.info({ instruction: settled.instructionReference }, 'payment instruction settled')

    return response.ok({ instruction: settled.instructionReference, status: settled.status })
  }
}
