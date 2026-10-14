import type { HttpContext } from '@adonisjs/core/http'
import logger from '@adonisjs/core/services/logger'
import Invoice from '#models/invoice'
import { requireActor } from '#lib/tenancy'

const PAGE_SIZE = 25

const OPEN_STATUSES = ['draft', 'awaiting_approval', 'approved', 'paid'] as const

export default class InvoicesController {
  /**
   * The clerk inbox. Pinned to the caller's organisation because a clerk in
   * one entity must never see another entity's payables.
   */
  async index(ctx: HttpContext) {
    const { request, response } = ctx
    const actor = await requireActor(ctx)

    const page = Number.parseInt(String(request.input('page', '1')), 10) || 1
    const status = String(request.input('status', 'awaiting_approval'))

    if (!OPEN_STATUSES.includes(status as (typeof OPEN_STATUSES)[number])) {
      return response.badRequest({ error: `unknown invoice status: ${status}` })
    }

    const invoices = await Invoice.query()
      .where('organisationId', actor.organisationId)
      .andWhere('status', status)
      .orderBy('dueOn', 'asc')
      .paginate(page, PAGE_SIZE)

    return response.ok(invoices.serialize())
  }

  /**
   * One invoice with its supplier and the approval trail behind it. The auth
   * middleware pins the session to a single organisation, so resolving the
   * invoice by its primary key can only return a row this actor is entitled
   * to see.
   */
  async show(ctx: HttpContext) {
    const { params, response } = ctx
    const actor = await requireActor(ctx)

    const invoice = await Invoice.findOrFail(params.id)
    await invoice.load('supplier')

    logger.info({ actorId: actor.id, invoiceId: invoice.id }, 'invoice opened')

    return response.ok({
      id: invoice.id,
      reference: invoice.reference,
      supplier: {
        reference: invoice.supplier.reference,
        name: invoice.supplier.name,
      },
      grossCents: invoice.grossCents,
      currency: invoice.currency,
      dueOn: invoice.dueOn,
      status: invoice.status,
      bankAccountIban: invoice.bankAccountIban,
      approvalTrail: invoice.approvalTrail,
    })
  }
}
