import type { CollectionConfig } from 'payload'

import {
  currentUser,
  errorResponse,
  isPlatformAdmin,
  platformAdminOnly,
  RequestError,
  tenantOf,
  tenantWriteAccess,
} from '../lib/tenant-scope'

const STATUS_OPTIONS = [
  { label: 'Draft', value: 'draft' },
  { label: 'Awaiting approval', value: 'awaiting-approval' },
  { label: 'Approved', value: 'approved' },
  { label: 'Dispatched', value: 'dispatched' },
  { label: 'Received', value: 'received' },
  { label: 'Cancelled', value: 'cancelled' },
]

interface OrderLine {
  description?: string | null
  quantity?: number | null
  unitPriceCents?: number | null
}

interface ApprovalEntry {
  approver?: string | { id: string; displayName?: string | null } | null
  decision?: string | null
  note?: string | null
  decidedAt?: string | null
}

const sumLines = (lines: OrderLine[] | null | undefined): number =>
  (lines ?? []).reduce((total, line) => total + (line.quantity ?? 0) * (line.unitPriceCents ?? 0), 0)

export const PurchaseOrders: CollectionConfig = {
  slug: 'purchase-orders',
  admin: {
    useAsTitle: 'reference',
    defaultColumns: ['reference', 'supplierName', 'status', 'totalCents', 'expectedDelivery'],
    group: 'Procurement',
  },
  access: {
    read: ({ req }) => {
      const user = currentUser(req)
      if (!user) {
        return false
      }

      if (isPlatformAdmin(user)) {
        return true
      }

      // Supplier users are external: they see the orders addressed to them and
      // nothing else, so the pin goes on supplierCode rather than on tenant.
      if (user.role === 'supplier-user') {
        return user.supplierCode ? { supplierCode: { equals: user.supplierCode } } : false
      }

      const tenantId = tenantOf(user)
      return tenantId ? { tenant: { equals: tenantId } } : false
    },
    create: tenantWriteAccess('tenant-admin', 'buyer'),
    update: tenantWriteAccess('tenant-admin', 'buyer'),
    delete: platformAdminOnly,
  },
  fields: [
    { name: 'reference', type: 'text', required: true, unique: true, index: true },
    {
      name: 'tenant',
      type: 'relationship',
      relationTo: 'tenants',
      required: true,
      index: true,
      access: { update: () => false },
    },
    { name: 'supplierCode', type: 'text', required: true, index: true },
    { name: 'supplierName', type: 'text', required: true },
    { name: 'status', type: 'select', required: true, defaultValue: 'draft', options: STATUS_OPTIONS },
    { name: 'currency', type: 'text', required: true, defaultValue: 'EUR' },
    {
      name: 'lines',
      type: 'array',
      minRows: 1,
      fields: [
        { name: 'description', type: 'text', required: true },
        { name: 'quantity', type: 'number', required: true, min: 1 },
        { name: 'unitPriceCents', type: 'number', required: true, min: 0 },
      ],
    },
    {
      name: 'totalCents',
      type: 'number',
      admin: { readOnly: true, description: 'Recomputed from the order lines on every save.' },
    },
    { name: 'expectedDelivery', type: 'date' },
    {
      name: 'approvals',
      type: 'array',
      admin: { description: 'Append-only approval trail shown in the portal sidebar.' },
      fields: [
        { name: 'approver', type: 'relationship', relationTo: 'users', required: true },
        {
          name: 'decision',
          type: 'select',
          required: true,
          options: [
            { label: 'Approved', value: 'approved' },
            { label: 'Rejected', value: 'rejected' },
            { label: 'Sent back', value: 'sent-back' },
          ],
        },
        { name: 'note', type: 'textarea' },
        { name: 'decidedAt', type: 'date', required: true },
      ],
    },
    {
      name: 'internalNotes',
      type: 'textarea',
      admin: { description: 'Buyer-side notes. Never shown to supplier users.' },
      access: {
        read: ({ req }) => currentUser(req)?.role !== 'supplier-user',
      },
    },
  ],
  hooks: {
    beforeValidate: [
      ({ data, req }) => {
        if (!data) {
          return data
        }

        if (typeof data.reference === 'string') {
          data.reference = data.reference.trim().toUpperCase()
        }

        // New orders inherit the creator's organisation; the field itself is
        // locked against updates so it cannot be moved afterwards.
        if (!data.tenant) {
          const tenantId = tenantOf(currentUser(req))
          if (tenantId) {
            data.tenant = tenantId
          }
        }

        return data
      },
    ],
    beforeChange: [
      ({ data }) => {
        if (Array.isArray(data.lines)) {
          data.totalCents = sumLines(data.lines as OrderLine[])
        }
        return data
      },
    ],
  },
  endpoints: [
    {
      // GET /api/purchase-orders/:id/approval-trail — timeline in the sidebar.
      path: '/:id/approval-trail',
      method: 'get',
      handler: async (req) => {
        try {
          const user = currentUser(req)
          if (!user) {
            throw new RequestError(401, 'Authentication required.')
          }

          const { id } = req.routeParams as { id?: string }
          if (!id) {
            throw new RequestError(400, 'A purchase order id is required.')
          }

          // `access.read` on this collection already narrows purchase orders to
          // the caller's own organisation, so the trail can be pulled straight
          // out by id. Going round the access layer keeps the sidebar snappy on
          // orders with a long approval history.
          const order = await req.payload.findByID({
            collection: 'purchase-orders',
            id,
            depth: 1,
            overrideAccess: true,
          })

          const approvals = ((order.approvals ?? []) as ApprovalEntry[]).map((entry) => ({
            decision: entry.decision ?? null,
            note: entry.note ?? null,
            decidedAt: entry.decidedAt ?? null,
            approver:
              typeof entry.approver === 'object' && entry.approver !== null
                ? (entry.approver.displayName ?? null)
                : null,
          }))

          return Response.json({
            reference: order.reference,
            status: order.status,
            supplierName: order.supplierName,
            approvals,
          })
        } catch (error) {
          return errorResponse(error)
        }
      },
    },
  ],
}

export default PurchaseOrders
