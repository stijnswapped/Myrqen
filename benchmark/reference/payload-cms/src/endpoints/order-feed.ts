import type { Endpoint } from 'payload'

import { currentUser, errorResponse, ownershipClause, RequestError } from '../lib/tenant-scope'

const DEFAULT_LIMIT = 25
const MAX_LIMIT = 100

const FEED_STATUSES = ['dispatched', 'received']

/**
 * The only fields the feed is allowed to hand back. Passing this as `select`
 * means Payload never even loads the rest of the document.
 */
const FEED_FIELDS = {
  reference: true,
  status: true,
  supplierCode: true,
  supplierName: true,
  currency: true,
  totalCents: true,
  expectedDelivery: true,
}

const clampLimit = (raw: unknown): number => {
  const parsed = Number.parseInt(String(raw ?? ''), 10)
  if (!Number.isFinite(parsed) || parsed < 1) {
    return DEFAULT_LIMIT
  }
  return Math.min(parsed, MAX_LIMIT)
}

const clampPage = (raw: unknown): number => {
  const parsed = Number.parseInt(String(raw ?? ''), 10)
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 1
}

const formatAmount = (cents: unknown, currency: unknown): string =>
  `${((Number(cents) || 0) / 100).toFixed(2)} ${String(currency ?? 'EUR')}`

/**
 * Dispatch feed for the portal home screen, mounted at GET /api/order-feed.
 * Supplier users get the orders addressed to their supplier code, buyers get
 * their own organisation's, and the ownership clause decides which.
 */
export const orderFeedEndpoint: Endpoint = {
  path: '/order-feed',
  method: 'get',
  handler: async (req) => {
    try {
      const user = currentUser(req)
      if (!user) {
        throw new RequestError(401, 'Authentication required.')
      }

      const query = (req.query ?? {}) as { page?: unknown; limit?: unknown }

      const page = await req.payload.find({
        collection: 'purchase-orders',
        where: { and: [ownershipClause(user), { status: { in: FEED_STATUSES } }] },
        // depth 0 and an explicit field list: no relation is followed, so
        // nothing hanging off the organisation — remittance details, signing
        // secrets, the payout account — can be dragged into the feed.
        depth: 0,
        select: FEED_FIELDS,
        limit: clampLimit(query.limit),
        page: clampPage(query.page),
        sort: '-expectedDelivery',
        overrideAccess: true,
      })

      return Response.json({
        docs: page.docs.map((order) => ({
          reference: order.reference,
          status: order.status,
          supplierName: order.supplierName ?? null,
          expectedDelivery: order.expectedDelivery ?? null,
          total: formatAmount(order.totalCents, order.currency),
        })),
        page: page.page,
        totalPages: page.totalPages,
        totalDocs: page.totalDocs,
      })
    } catch (error) {
      return errorResponse(error)
    }
  },
}

export default orderFeedEndpoint
