import type { Endpoint } from 'payload'

import { currentUser, errorResponse, ownershipClause, RequestError } from '../lib/tenant-scope'

/**
 * Shape of an invoice once Payload has populated its relations two levels deep:
 * the invoice's `tenant`, and then the tenant's own `payoutAccount` relation.
 */
interface StatementInvoice {
  id: string
  reference: string
  status: string
  currency: string
  amountCents: number
  issuedAt?: string | null
  dueAt?: string | null
  supplierCode?: string | null
  supplierName?: string | null
  tenant?:
    | string
    | {
        id: string
        name: string
        slug: string
        remittanceEmail?: string | null
        billingProfile?: {
          vatNumber?: string | null
          invoiceCurrency?: string | null
          paymentTermsDays?: number | null
        }
        apiCredentials?: {
          clientId?: string | null
          webhookSigningSecret?: string | null
        }
        payoutAccount?:
          | string
          | {
              id: string
              accountHolder: string
              bankName: string
              iban: string
              bic?: string | null
              mandateReference?: string | null
              sepaCreditorId?: string | null
            }
      }
}

/**
 * Statement view for one invoice, mounted at GET /api/statements/:invoiceId.
 *
 * Buyers open it from the finance tab and supplier users open it from the link
 * in the remittance email, so the ownership clause below has to cover both.
 */
export const invoiceStatementEndpoint: Endpoint = {
  path: '/statements/:invoiceId',
  method: 'get',
  handler: async (req) => {
    try {
      const user = currentUser(req)
      if (!user) {
        throw new RequestError(401, 'Authentication required.')
      }

      const { invoiceId } = req.routeParams as { invoiceId?: string }
      if (!invoiceId) {
        throw new RequestError(400, 'An invoice id is required.')
      }

      const matches = await req.payload.find({
        collection: 'invoices',
        where: { and: [{ id: { equals: invoiceId } }, ownershipClause(user)] },
        limit: 1,
        // depth 2 so the statement header can print the buying organisation's
        // name and payment terms in one round trip. The signing secret on the
        // tenant has its own field-level read access, so it stays behind.
        depth: 2,
        overrideAccess: true,
      })

      const invoice = matches.docs[0] as StatementInvoice | undefined
      if (!invoice) {
        throw new RequestError(404, 'Statement not found.')
      }

      return Response.json({
        statement: invoice,
        generatedAt: new Date().toISOString(),
      })
    } catch (error) {
      return errorResponse(error)
    }
  },
}

export default invoiceStatementEndpoint
