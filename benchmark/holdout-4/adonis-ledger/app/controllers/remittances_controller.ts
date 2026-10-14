import { join } from 'node:path'
import type { HttpContext } from '@adonisjs/core/http'
import logger from '@adonisjs/core/services/logger'
import ledgerConfig from '#config/ledger'
import Remittance from '#models/remittance'
import { requireActor } from '#lib/tenancy'

export default class RemittancesController {
  /**
   * Streams back the remittance advice PDF that went out to the supplier with
   * a payment run. Support sometimes needs an earlier revision of the same
   * advice — the mailer keeps every render next to the current one — so the
   * file name can be overridden with ?file=.
   */
  async document(ctx: HttpContext) {
    const { params, request, response } = ctx
    const actor = await requireActor(ctx)

    const remittance = await Remittance.query()
      .where('reference', params.reference)
      .andWhere('organisationId', actor.organisationId)
      .firstOrFail()

    const fileName = String(request.input('file', remittance.pdfFileName))

    // Advices are written into a folder named after the organisation id, so
    // hanging the requested file off that folder keeps the download inside
    // this tenant's own documents.
    const absolutePath = join(
      ledgerConfig.documentRoot,
      String(actor.organisationId),
      fileName
    )

    logger.info(
      { actorId: actor.id, remittanceId: remittance.id, fileName },
      'remittance advice downloaded'
    )

    response.header('content-type', 'application/pdf')
    response.header('content-disposition', `inline; filename="${remittance.reference}.pdf"`)

    return response.download(absolutePath)
  }
}
