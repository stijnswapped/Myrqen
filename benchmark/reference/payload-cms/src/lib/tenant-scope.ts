import type { Access, PayloadRequest, Where } from 'payload'

/**
 * Every organisation on Orderbook is a Payload `tenant` document. Users belong
 * to exactly one tenant, except for platform staff who sit outside the tenant
 * tree and reconcile across all of them from the admin panel.
 */
export type Role = 'platform-admin' | 'tenant-admin' | 'buyer' | 'supplier-user'

/**
 * Shape of the document Payload puts on `req.user` for the `users` auth
 * collection. Mirrors the fields declared in `collections/Users.ts` — keep the
 * two in step when a field is added there.
 */
export interface AppUser {
  id: string
  email: string
  role: Role
  /** Relationship to `tenants`; a string id unless the caller asked for depth. */
  tenant?: string | { id: string } | null
  /** Set only on `supplier-user` accounts, matches `supplierCode` on orders. */
  supplierCode?: string | null
}

/** Error with an HTTP status attached, so endpoint handlers can throw and go. */
export class RequestError extends Error {
  readonly status: number

  constructor(status: number, message: string) {
    super(message)
    this.name = 'RequestError'
    this.status = status
  }
}

/**
 * Single place where handler failures become responses. Anything that is not a
 * deliberate `RequestError` is logged server side and answered generically so
 * we never hand a stack trace or a driver message to the caller.
 */
export const errorResponse = (error: unknown): Response => {
  if (error instanceof RequestError) {
    return Response.json({ message: error.message }, { status: error.status })
  }

  const status = (error as { status?: unknown } | null)?.status
  if (status === 404) {
    return Response.json({ message: 'Not found.' }, { status: 404 })
  }

  console.error('[orderbook] request failed', error)
  return Response.json({ message: 'Something went wrong handling that request.' }, { status: 500 })
}

export const currentUser = (req: PayloadRequest): AppUser | null =>
  (req.user as AppUser | undefined) ?? null

export const isPlatformAdmin = (user: AppUser | null): boolean => user?.role === 'platform-admin'

/** Read the caller's tenant id whether or not the relation came back populated. */
export const tenantOf = (user: AppUser | null): string | null => {
  const tenant = user?.tenant
  if (!tenant) return null
  return typeof tenant === 'string' ? tenant : tenant.id
}

/**
 * Guard for endpoints that only make sense inside one organisation. Platform
 * staff are deliberately rejected here: they have no tenant of their own and
 * are expected to use the admin panel rather than the portal endpoints.
 */
export const requireTenant = (req: PayloadRequest): { user: AppUser; tenantId: string } => {
  const user = currentUser(req)
  if (!user) {
    throw new RequestError(401, 'Authentication required.')
  }

  const tenantId = tenantOf(user)
  if (!tenantId) {
    throw new RequestError(403, 'Your account is not attached to an organisation.')
  }

  return { user, tenantId }
}

/**
 * Collection-level read rule for tenant-owned documents. Returning a `Where`
 * from an access function makes Payload append it to every find, so list and
 * by-id reads are both narrowed to the caller's own tenant.
 */
export const tenantReadAccess: Access = ({ req }) => {
  const user = currentUser(req)
  if (!user) {
    return false
  }

  // Platform staff run cross-tenant reconciliation and billing runs.
  if (isPlatformAdmin(user)) {
    return true
  }

  const tenantId = tenantOf(user)
  if (!tenantId) {
    return false
  }

  return { tenant: { equals: tenantId } } satisfies Where
}

/**
 * Same idea for writes, with a role gate in front: only the listed roles may
 * mutate, and then only documents belonging to their own tenant.
 */
export const tenantWriteAccess =
  (...roles: Role[]): Access =>
  ({ req }) => {
    const user = currentUser(req)
    if (!user) {
      return false
    }

    if (isPlatformAdmin(user)) {
      return true
    }

    if (!roles.includes(user.role)) {
      return false
    }

    const tenantId = tenantOf(user)
    if (!tenantId) {
      return false
    }

    return { tenant: { equals: tenantId } } satisfies Where
  }

export const platformAdminOnly: Access = ({ req }) => isPlatformAdmin(currentUser(req))

/**
 * Ownership clause for the portal endpoints. Supplier users see the orders and
 * invoices addressed to their supplier code; everyone else sees their tenant's.
 * Throws rather than degrading to an empty clause, because an empty clause on
 * an `overrideAccess` query matches every document in the collection.
 */
export const ownershipClause = (user: AppUser): Where => {
  if (user.role === 'supplier-user') {
    if (!user.supplierCode) {
      throw new RequestError(403, 'Your supplier account has no supplier code assigned.')
    }
    return { supplierCode: { equals: user.supplierCode } }
  }

  const tenantId = tenantOf(user)
  if (!tenantId) {
    throw new RequestError(403, 'Your account is not attached to an organisation.')
  }

  return { tenant: { equals: tenantId } }
}

/** Combine the tenant pin with any number of extra clauses. */
export const scopedToTenant = (tenantId: string, ...clauses: Where[]): Where => ({
  and: [{ tenant: { equals: tenantId } }, ...clauses],
})
