import type { CollectionConfig } from 'payload'

import {
  currentUser,
  errorResponse,
  isPlatformAdmin,
  platformAdminOnly,
  RequestError,
  requireTenant,
  tenantOf,
} from '../lib/tenant-scope'

const CURRENCIES = ['EUR', 'GBP', 'USD']
const MAX_PAYMENT_TERMS_DAYS = 120
const VAT_PATTERN = /^[A-Z]{2}[0-9A-Z]{8,12}$/
const ORDER_PREFIX_PATTERN = /^[A-Z]{2,6}$/

/**
 * Fields of the billing profile an organisation admin is allowed to maintain
 * themselves. Anything outside this list (name, slug, apiCredentials, the
 * payout account relation) is changed by support, not by the customer.
 */
const EDITABLE_BILLING_FIELDS = ['vatNumber', 'invoiceCurrency', 'paymentTermsDays', 'purchaseOrderPrefix'] as const

type EditableBillingField = (typeof EDITABLE_BILLING_FIELDS)[number]

const validateBillingField = (field: EditableBillingField, value: unknown): unknown => {
  switch (field) {
    case 'vatNumber': {
      const vatNumber = String(value ?? '').trim().toUpperCase()
      if (!VAT_PATTERN.test(vatNumber)) {
        throw new RequestError(422, 'vatNumber is not a valid EU VAT identifier.')
      }
      return vatNumber
    }
    case 'invoiceCurrency': {
      const currency = String(value ?? '').trim().toUpperCase()
      if (!CURRENCIES.includes(currency)) {
        throw new RequestError(422, `invoiceCurrency must be one of ${CURRENCIES.join(', ')}.`)
      }
      return currency
    }
    case 'paymentTermsDays': {
      const days = Number(value)
      if (!Number.isInteger(days) || days < 0 || days > MAX_PAYMENT_TERMS_DAYS) {
        throw new RequestError(422, `paymentTermsDays must be a whole number of days up to ${MAX_PAYMENT_TERMS_DAYS}.`)
      }
      return days
    }
    case 'purchaseOrderPrefix': {
      const prefix = String(value ?? '').trim().toUpperCase()
      if (!ORDER_PREFIX_PATTERN.test(prefix)) {
        throw new RequestError(422, 'purchaseOrderPrefix must be 2 to 6 letters.')
      }
      return prefix
    }
    default:
      throw new RequestError(422, 'Unknown billing field.')
  }
}

export const Tenants: CollectionConfig = {
  slug: 'tenants',
  admin: {
    useAsTitle: 'name',
    defaultColumns: ['name', 'slug', 'remittanceEmail'],
    group: 'Organisation',
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

      const tenantId = tenantOf(user)
      // `tenants` is the tenant itself, so the pin goes on `id`, not `tenant`.
      return tenantId ? { id: { equals: tenantId } } : false
    },
    create: platformAdminOnly,
    update: ({ req }) => {
      const user = currentUser(req)
      if (!user) {
        return false
      }

      if (isPlatformAdmin(user)) {
        return true
      }

      if (user.role !== 'tenant-admin') {
        return false
      }

      const tenantId = tenantOf(user)
      return tenantId ? { id: { equals: tenantId } } : false
    },
    delete: platformAdminOnly,
  },
  fields: [
    { name: 'name', type: 'text', required: true },
    {
      name: 'slug',
      type: 'text',
      required: true,
      unique: true,
      index: true,
      access: { update: ({ req }) => isPlatformAdmin(currentUser(req)) },
    },
    { name: 'remittanceEmail', type: 'email', required: true },
    {
      name: 'billingProfile',
      type: 'group',
      fields: [
        { name: 'vatNumber', type: 'text' },
        { name: 'invoiceCurrency', type: 'text', defaultValue: 'EUR' },
        { name: 'paymentTermsDays', type: 'number', defaultValue: 30 },
        { name: 'purchaseOrderPrefix', type: 'text', defaultValue: 'PO' },
      ],
    },
    {
      name: 'payoutAccount',
      type: 'relationship',
      relationTo: 'payout-accounts',
      hasMany: false,
      access: { update: ({ req }) => isPlatformAdmin(currentUser(req)) },
      admin: { description: 'Bank account remittance advice is issued against.' },
    },
    {
      name: 'apiCredentials',
      type: 'group',
      access: {
        // The signing secret is staff-only; organisation admins rotate it
        // through a support request rather than reading it back.
        read: ({ req }) => isPlatformAdmin(currentUser(req)),
        update: ({ req }) => isPlatformAdmin(currentUser(req)),
      },
      fields: [
        { name: 'clientId', type: 'text' },
        { name: 'webhookSigningSecret', type: 'text' },
      ],
    },
    {
      name: 'suspendedAt',
      type: 'date',
      access: { update: ({ req }) => isPlatformAdmin(currentUser(req)) },
      admin: { position: 'sidebar' },
    },
  ],
  endpoints: [
    {
      // PATCH /api/tenants/:id/billing-profile — the "Billing details" form.
      path: '/:id/billing-profile',
      method: 'patch',
      handler: async (req) => {
        try {
          const { user, tenantId } = requireTenant(req)
          const { id } = req.routeParams as { id?: string }

          if (!id) {
            throw new RequestError(400, 'An organisation id is required.')
          }

          if (id !== tenantId) {
            throw new RequestError(403, 'You can only edit your own organisation.')
          }

          if (user.role !== 'tenant-admin') {
            throw new RequestError(403, 'Only organisation admins can edit billing details.')
          }

          const body = await req.json()
          if (!body || typeof body !== 'object') {
            throw new RequestError(400, 'A JSON body is required.')
          }

          // Copy across the fields on the allow list and nothing else, so a
          // key like `apiCredentials` or `suspendedAt` in the body is simply
          // never looked at.
          const billingProfile: Record<string, unknown> = {}
          for (const field of EDITABLE_BILLING_FIELDS) {
            if (body[field] !== undefined) {
              billingProfile[field] = validateBillingField(field, body[field])
            }
          }

          if (Object.keys(billingProfile).length === 0) {
            throw new RequestError(422, `Send at least one of ${EDITABLE_BILLING_FIELDS.join(', ')}.`)
          }

          const updated = await req.payload.update({
            collection: 'tenants',
            id: tenantId,
            data: { billingProfile },
            depth: 0,
            overrideAccess: true,
          })

          return Response.json({
            id: updated.id,
            billingProfile: updated.billingProfile ?? null,
          })
        } catch (error) {
          return errorResponse(error)
        }
      },
    },
  ],
}

export default Tenants
