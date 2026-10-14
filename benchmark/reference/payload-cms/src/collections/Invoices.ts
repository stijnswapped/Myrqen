import type { CollectionConfig, Where } from 'payload'

import {
  currentUser,
  errorResponse,
  isPlatformAdmin,
  ownershipClause,
  platformAdminOnly,
  RequestError,
  tenantOf,
  tenantWriteAccess,
} from '../lib/tenant-scope'

const STATUS_OPTIONS = [
  { label: 'Draft', value: 'draft' },
  { label: 'Issued', value: 'issued' },
  { label: 'Part paid', value: 'part-paid' },
  { label: 'Paid', value: 'paid' },
  { label: 'Void', value: 'void' },
]

interface PaymentEvent {
  kind?: string | null
  amountCents?: number | null
  occurredAt?: string | null
  providerReference?: string | null
}

export const Invoices: CollectionConfig = {
  slug: 'invoices',
  admin: {
    useAsTitle: 'reference',
    defaultColumns: ['reference', 'supplierName', 'status', 'amountCents', 'dueAt'],
    group: 'Finance',
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

      if (user.role === 'supplier-user') {
        return user.supplierCode ? { supplierCode: { equals: user.supplierCode } } : false
      }

      const tenantId = tenantOf(user)
      return tenantId ? { tenant: { equals: tenantId } } : false
    },
    create: tenantWriteAccess('tenant-admin'),
    update: tenantWriteAccess('tenant-admin'),
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
    { name: 'purchaseOrder', type: 'relationship', relationTo: 'purchase-orders' },
    { name: 'supplierCode', type: 'text', required: true, index: true },
    { name: 'supplierName', type: 'text', required: true },
    { name: 'status', type: 'select', required: true, defaultValue: 'draft', options: STATUS_OPTIONS },
    { name: 'currency', type: 'text', required: true, defaultValue: 'EUR' },
    { name: 'amountCents', type: 'number', required: true, min: 0 },
    { name: 'issuedAt', type: 'date' },
    { name: 'dueAt', type: 'date' },
    {
      name: 'paymentEvents',
      type: 'array',
      admin: { description: 'Written by the payment provider webhook, read-only in the panel.' },
      access: { update: ({ req }) => isPlatformAdmin(currentUser(req)) },
      fields: [
        {
          name: 'kind',
          type: 'select',
          required: true,
          options: [
            { label: 'Authorised', value: 'authorised' },
            { label: 'Settled', value: 'settled' },
            { label: 'Refunded', value: 'refunded' },
            { label: 'Chargeback', value: 'chargeback' },
          ],
        },
        { name: 'amountCents', type: 'number', required: true },
        { name: 'occurredAt', type: 'date', required: true },
        { name: 'providerReference', type: 'text' },
      ],
    },
  ],
  hooks: {
    beforeValidate: [
      ({ data }) => {
        if (data && typeof data.reference === 'string') {
          data.reference = data.reference.trim().toUpperCase()
        }
        return data
      },
    ],
  },
  endpoints: [
    {
      // GET /api/invoices/:id/payment-timeline — payment history for one invoice.
      path: '/:id/payment-timeline',
      method: 'get',
      handler: async (req) => {
        try {
          const user = currentUser(req)
          if (!user) {
            throw new RequestError(401, 'Authentication required.')
          }

          const { id } = req.routeParams as { id?: string }
          if (!id) {
            throw new RequestError(400, 'An invoice id is required.')
          }

          // Pin the lookup to whatever the caller owns and let the id be one
          // clause of that filter, so a stranger's invoice id simply matches
          // nothing. Platform staff are the only callers with no owner clause.
          const scope: Where = isPlatformAdmin(user)
            ? { id: { equals: id } }
            : { and: [{ id: { equals: id } }, ownershipClause(user)] }

          const matches = await req.payload.find({
            collection: 'invoices',
            where: scope,
            limit: 1,
            depth: 0,
            overrideAccess: true,
          })

          const invoice = matches.docs[0]
          if (!invoice) {
            throw new RequestError(404, 'Invoice not found.')
          }

          const events = ((invoice.paymentEvents ?? []) as PaymentEvent[])
            .slice()
            .sort((left, right) => String(left.occurredAt).localeCompare(String(right.occurredAt)))
            .map((event) => ({
              kind: event.kind ?? null,
              amountCents: event.amountCents ?? 0,
              occurredAt: event.occurredAt ?? null,
            }))

          return Response.json({
            reference: invoice.reference,
            status: invoice.status,
            amountCents: invoice.amountCents,
            currency: invoice.currency,
            dueAt: invoice.dueAt ?? null,
            events,
          })
        } catch (error) {
          return errorResponse(error)
        }
      },
    },
  ],
}

export default Invoices
