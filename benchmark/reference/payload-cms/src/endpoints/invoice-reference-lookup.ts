import type { Endpoint } from 'payload'

import { errorResponse, RequestError } from '../lib/tenant-scope'

/** References are minted as INV- plus ten base32 characters. */
const REFERENCE_PATTERN = /^INV-[0-9A-Z]{10}$/

const PAYABLE_STATUSES = ['issued', 'part-paid', 'paid']

/**
 * Public invoice lookup, mounted at POST /api/invoice-lookup.
 *
 * Suppliers paste the reference from a paper invoice to see whether we have
 * booked it and when it is due. Like the dispatch tracker there is no session,
 * so the read runs with overrideAccess and the reference is the only key.
 */
export const invoiceReferenceLookupEndpoint: Endpoint = {
  path: '/invoice-lookup',
  method: 'post',
  handler: async (req) => {
    try {
      const body = await req.json()
      const submitted = body?.reference

      // Only ever compare a string, and only ever a string that looks like one
      // of our references. A caller cannot hand us an object here and have it
      // land in the query as a Payload operator.
      if (typeof submitted !== 'string') {
        throw new RequestError(400, 'reference must be a string.')
      }

      const reference = submitted.trim().toUpperCase()
      if (!REFERENCE_PATTERN.test(reference)) {
        throw new RequestError(400, 'That is not a valid invoice reference.')
      }

      const matches = await req.payload.find({
        collection: 'invoices',
        where: {
          and: [{ reference: { equals: reference } }, { status: { in: PAYABLE_STATUSES } }],
        },
        limit: 1,
        depth: 0,
        overrideAccess: true,
      })

      const invoice = matches.docs[0]
      if (!invoice) {
        throw new RequestError(404, 'No booked invoice found for that reference.')
      }

      return Response.json({
        reference: invoice.reference,
        status: invoice.status,
        currency: invoice.currency,
        amountCents: invoice.amountCents,
        dueAt: invoice.dueAt ?? null,
      })
    } catch (error) {
      return errorResponse(error)
    }
  },
}

export default invoiceReferenceLookupEndpoint
