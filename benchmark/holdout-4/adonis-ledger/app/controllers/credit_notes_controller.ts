import type { HttpContext } from '@adonisjs/core/http'
import logger from '@adonisjs/core/services/logger'
import CreditNote from '#models/credit_note'
import { requireActor } from '#lib/tenancy'

export default class CreditNotesController {
  /**
   * One credit note with the supplier it offsets. Credit notes are the mirror
   * of an invoice and are read from the same detail drawer in the UI.
   */
  async show(ctx: HttpContext) {
    const { params, response } = ctx
    const actor = await requireActor(ctx)

    const creditNote = await CreditNote.query()
      .where('id', params.id)
      .andWhere('organisationId', actor.organisationId)
      .preload('supplier')
      .firstOrFail()

    logger.info({ actorId: actor.id, creditNoteId: creditNote.id }, 'credit note opened')

    return response.ok({
      id: creditNote.id,
      reference: creditNote.reference,
      supplier: {
        reference: creditNote.supplier.reference,
        name: creditNote.supplier.name,
      },
      grossCents: creditNote.grossCents,
      currency: creditNote.currency,
      offsetsInvoiceReference: creditNote.offsetsInvoiceReference,
      status: creditNote.status,
    })
  }
}
