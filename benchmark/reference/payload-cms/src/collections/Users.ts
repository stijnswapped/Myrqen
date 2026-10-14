import type { CollectionConfig } from 'payload'

import {
  currentUser,
  errorResponse,
  isPlatformAdmin,
  platformAdminOnly,
  RequestError,
  tenantOf,
  tenantReadAccess,
  tenantWriteAccess,
} from '../lib/tenant-scope'

const DISPLAY_NAME_MAX = 80
const PHONE_PATTERN = /^\+?[0-9 ()-]{6,24}$/

const ROLE_OPTIONS = [
  { label: 'Platform admin', value: 'platform-admin' },
  { label: 'Organisation admin', value: 'tenant-admin' },
  { label: 'Buyer', value: 'buyer' },
  { label: 'Supplier user', value: 'supplier-user' },
]

export const Users: CollectionConfig = {
  slug: 'users',
  auth: {
    tokenExpiration: 60 * 60 * 8,
    maxLoginAttempts: 8,
    lockTime: 10 * 60 * 1000,
    verify: false,
  },
  admin: {
    useAsTitle: 'email',
    defaultColumns: ['email', 'displayName', 'role', 'tenant'],
    group: 'Organisation',
  },
  access: {
    read: tenantReadAccess,
    create: tenantWriteAccess('tenant-admin'),
    update: ({ req, id }) => {
      const user = currentUser(req)
      if (!user) {
        return false
      }

      if (isPlatformAdmin(user)) {
        return true
      }

      // Organisation admins manage the accounts inside their own organisation.
      if (user.role === 'tenant-admin') {
        const tenantId = tenantOf(user)
        return tenantId ? { tenant: { equals: tenantId } } : false
      }

      // Everyone else may only touch their own record.
      return id === user.id
    },
    delete: platformAdminOnly,
  },
  fields: [
    {
      name: 'displayName',
      type: 'text',
      required: true,
      maxLength: DISPLAY_NAME_MAX,
    },
    {
      name: 'role',
      type: 'select',
      required: true,
      defaultValue: 'buyer',
      options: ROLE_OPTIONS,
      access: {
        // Only staff and organisation admins may move an account between roles.
        update: ({ req }) => {
          const user = currentUser(req)
          return isPlatformAdmin(user) || user?.role === 'tenant-admin'
        },
      },
      admin: {
        description: 'Determines which portal screens and API scopes the account can reach.',
      },
    },
    {
      name: 'tenant',
      type: 'relationship',
      relationTo: 'tenants',
      hasMany: false,
      admin: {
        condition: (data) => data?.role !== 'platform-admin',
        description: 'Organisation this account belongs to. Platform staff leave this empty.',
      },
      access: {
        update: ({ req }) => isPlatformAdmin(currentUser(req)),
      },
    },
    {
      name: 'supplierCode',
      type: 'text',
      admin: {
        condition: (data) => data?.role === 'supplier-user',
        description: 'Matched against supplierCode on purchase orders and invoices.',
      },
      access: {
        update: ({ req }) => {
          const user = currentUser(req)
          return isPlatformAdmin(user) || user?.role === 'tenant-admin'
        },
      },
    },
    {
      name: 'phone',
      type: 'text',
      validate: (value: string | null | undefined) => {
        if (!value) {
          return true
        }
        return PHONE_PATTERN.test(value) ? true : 'Enter a phone number we can dial.'
      },
    },
    {
      name: 'timezone',
      type: 'text',
      defaultValue: 'Europe/Amsterdam',
    },
    {
      name: 'digestFrequency',
      type: 'select',
      defaultValue: 'daily',
      options: [
        { label: 'Off', value: 'off' },
        { label: 'Daily', value: 'daily' },
        { label: 'Weekly', value: 'weekly' },
      ],
    },
    {
      name: 'profileUpdatedAt',
      type: 'date',
      admin: { readOnly: true, position: 'sidebar' },
    },
  ],
  hooks: {
    beforeValidate: [
      ({ data }) => {
        if (!data) {
          return data
        }
        if (typeof data.email === 'string') {
          data.email = data.email.trim().toLowerCase()
        }
        if (typeof data.displayName === 'string') {
          data.displayName = data.displayName.trim()
        }
        return data
      },
    ],
  },
  endpoints: [
    {
      // PATCH /api/users/me/profile — used by the "My details" screen.
      path: '/me/profile',
      method: 'patch',
      handler: async (req) => {
        try {
          const user = currentUser(req)
          if (!user) {
            throw new RequestError(401, 'Authentication required.')
          }

          const body = await req.json()
          if (!body || typeof body !== 'object') {
            throw new RequestError(400, 'A JSON body is required.')
          }

          if (typeof body.displayName !== 'string' || body.displayName.trim().length === 0) {
            throw new RequestError(422, 'displayName is required.')
          }

          if (body.displayName.trim().length > DISPLAY_NAME_MAX) {
            throw new RequestError(422, `displayName must be at most ${DISPLAY_NAME_MAX} characters.`)
          }

          if (body.phone !== undefined && body.phone !== null && !PHONE_PATTERN.test(String(body.phone))) {
            throw new RequestError(422, 'Enter a phone number we can dial.')
          }

          // The id is pinned to the caller, so nobody can patch somebody else's
          // account here, and `role`, `tenant` and `supplierCode` all carry
          // their own field-level access control — so the remaining keys in the
          // body can go through as they are.
          const updated = await req.payload.update({
            collection: 'users',
            id: user.id,
            data: {
              ...body,
              profileUpdatedAt: new Date().toISOString(),
            },
            depth: 0,
            overrideAccess: true,
          })

          return Response.json({
            id: updated.id,
            displayName: updated.displayName,
            phone: updated.phone ?? null,
            timezone: updated.timezone ?? null,
            digestFrequency: updated.digestFrequency ?? null,
            role: updated.role,
          })
        } catch (error) {
          return errorResponse(error)
        }
      },
    },
  ],
}

export default Users
