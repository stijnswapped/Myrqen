import { resolve, sep } from 'node:path'
import type { HttpContext } from '@adonisjs/core/http'
import logger from '@adonisjs/core/services/logger'
import ledgerConfig from '#config/ledger'
import SupplierDocument from '#models/supplier_document'
import { requireActor } from '#lib/tenancy'

export default class SupplierDocumentsController {
  /**
   * Streams a supplier's onboarding paperwork — bank mandate, VAT
   * certificate, insurance letter. Same storage tree as the remittance
   * advices, one folder per organisation.
   */
  async download(ctx: HttpContext) {
    const { params, response } = ctx
    const actor = await requireActor(ctx)

    const document = await SupplierDocument.query()
      .where('id', params.id)
      .andWhere('organisationId', actor.organisationId)
      .firstOrFail()

    const tenantRoot = resolve(ledgerConfig.documentRoot, String(actor.organisationId))
    const absolutePath = resolve(tenantRoot, document.storageKey)

    if (!absolutePath.startsWith(tenantRoot + sep)) {
      logger.warn(
        { actorId: actor.id, documentId: document.id, storageKey: document.storageKey },
        'document storage key resolved outside the tenant root'
      )

      return response.forbidden({ error: 'document is not readable' })
    }

    const downloadName = document.displayName.replace(/[^A-Za-z0-9._-]/g, '_')

    response.header('content-type', document.mimeType)
    response.header('content-disposition', `attachment; filename="${downloadName}"`)

    return response.download(absolutePath)
  }
}
