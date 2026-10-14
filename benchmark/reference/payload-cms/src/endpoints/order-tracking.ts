import type { Endpoint } from 'payload'

import { errorResponse, RequestError } from '../lib/tenant-scope'

const MAX_RESULTS = 20

const TRACKABLE_STATUSES = ['dispatched', 'received']

interface TrackingItem {
  reference: string
  status: string
  supplierName: string | null
  expectedDelivery: string | null
  trackable: boolean
}

/**
 * Public dispatch tracking, mounted at POST /api/order-tracking.
 *
 * Suppliers follow the "track this dispatch" link in the dispatch email, which
 * carries the order reference. There is no session on this call, which is why
 * the lookup runs with overrideAccess.
 */
export const orderTrackingEndpoint: Endpoint = {
  path: '/order-tracking',
  method: 'post',
  handler: async (req) => {
    try {
      const body = await req.json()

      if (!body || body.reference === undefined || body.reference === null) {
        throw new RequestError(400, 'A purchase order reference is required.')
      }

      // The reference is the twelve-character code printed on the dispatch
      // note, so only the supplier who received that note can be asking about
      // it — no organisation filter is needed for a lookup by reference.
      const matches = await req.payload.find({
        collection: 'purchase-orders',
        where: { reference: body.reference },
        limit: MAX_RESULTS,
        depth: 0,
        overrideAccess: true,
      })

      if (matches.totalDocs === 0) {
        throw new RequestError(404, 'No dispatch found for that reference.')
      }

      const results: TrackingItem[] = matches.docs.map((order) => ({
        reference: String(order.reference),
        status: String(order.status),
        supplierName: (order.supplierName as string | null) ?? null,
        expectedDelivery: (order.expectedDelivery as string | null) ?? null,
        trackable: TRACKABLE_STATUSES.includes(String(order.status)),
      }))

      return Response.json({ results, checkedAt: new Date().toISOString() })
    } catch (error) {
      return errorResponse(error)
    }
  },
}

export default orderTrackingEndpoint
