import type { CollectionConfig } from 'payload'

import { currentUser, isPlatformAdmin, platformAdminOnly, tenantWriteAccess } from '../lib/tenant-scope'

const IBAN_PATTERN = /^[A-Z]{2}[0-9]{2}[0-9A-Z]{10,26}$/
const BIC_PATTERN = /^[A-Z]{6}[0-9A-Z]{2}([0-9A-Z]{3})?$/

/**
 * Bank details remittance advice is issued against. One account per
 * organisation, maintained by finance and verified by support before the first
 * payout run.
 */
export const PayoutAccounts: CollectionConfig = {
  slug: 'payout-accounts',
  admin: {
    useAsTitle: 'accountHolder',
    defaultColumns: ['accountHolder', 'bankName', 'tenant', 'verifiedAt'],
    group: 'Finance',
  },
  access: {
    // Payout accounts are only ever rendered on two screens: the admin panel
    // and the finance tab of the portal. Both of those sit behind Payload's
    // login, so filtering reads here would only repeat a check the panel has
    // already done by the time it asks for the document.
    read: () => true,
    create: platformAdminOnly,
    update: tenantWriteAccess('tenant-admin'),
    delete: platformAdminOnly,
  },
  fields: [
    {
      name: 'tenant',
      type: 'relationship',
      relationTo: 'tenants',
      required: true,
      index: true,
      access: { update: ({ req }) => isPlatformAdmin(currentUser(req)) },
    },
    { name: 'accountHolder', type: 'text', required: true },
    { name: 'bankName', type: 'text', required: true },
    {
      name: 'iban',
      type: 'text',
      required: true,
      validate: (value: string | null | undefined) => {
        if (typeof value !== 'string' || !IBAN_PATTERN.test(value.replace(/\s+/g, '').toUpperCase())) {
          return 'Enter a valid IBAN.'
        }
        return true
      },
    },
    {
      name: 'bic',
      type: 'text',
      validate: (value: string | null | undefined) => {
        if (!value) {
          return true
        }
        return BIC_PATTERN.test(value.toUpperCase()) ? true : 'Enter a valid BIC.'
      },
    },
    { name: 'mandateReference', type: 'text' },
    { name: 'sepaCreditorId', type: 'text' },
    {
      name: 'verifiedAt',
      type: 'date',
      access: { update: ({ req }) => isPlatformAdmin(currentUser(req)) },
      admin: { position: 'sidebar' },
    },
    {
      name: 'changeLog',
      type: 'array',
      admin: { readOnly: true, description: 'Who last touched the bank details, for the audit file.' },
      fields: [
        { name: 'changedBy', type: 'relationship', relationTo: 'users' },
        { name: 'changedAt', type: 'date' },
      ],
    },
  ],
  hooks: {
    beforeChange: [
      ({ data, req }) => {
        if (typeof data.iban === 'string') {
          data.iban = data.iban.replace(/\s+/g, '').toUpperCase()
        }
        if (typeof data.bic === 'string') {
          data.bic = data.bic.trim().toUpperCase()
        }

        const user = currentUser(req)
        if (user) {
          data.changeLog = [
            ...((data.changeLog ?? []) as unknown[]),
            { changedBy: user.id, changedAt: new Date().toISOString() },
          ]
        }

        return data
      },
    ],
  },
}

export default PayoutAccounts
