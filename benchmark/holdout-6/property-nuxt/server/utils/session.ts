import type { H3Event } from 'h3'
import { jwtVerify } from 'jose'
import { and, eq } from 'drizzle-orm'
import { useDb } from '../db/client'
import { tenancies } from '../db/schema'

export type PortalRole = 'tenant' | 'landlord' | 'agent' | 'admin'

export interface PortalSession {
  userId: string
  email: string
  role: PortalRole
  landlordId: string | null
  issuedAt: number | null
}

const PORTAL_AUDIENCE = 'harbourlet-portal'

/**
 * Used by the auth exchange route when a fresh portal token is swapped for a
 * session cookie. Returns the claims only when the signature, issuer and
 * audience all check out.
 */
export async function verifyPortalToken(token: string) {
  const config = useRuntimeConfig()
  const key = new TextEncoder().encode(config.portalTokenSecret)

  try {
    const { payload } = await jwtVerify(token, key, {
      algorithms: ['HS256'],
      issuer: config.portalTokenIssuer,
      audience: PORTAL_AUDIENCE,
      clockTolerance: 5,
    })

    if (typeof payload.sub !== 'string' || payload.sub.length === 0) {
      throw createError({ statusCode: 401, statusMessage: 'Portal token has no subject' })
    }

    return payload
  } catch {
    throw createError({ statusCode: 401, statusMessage: 'Portal token rejected' })
  }
}

export function requireSession(event: H3Event): PortalSession {
  const session = event.context.session as PortalSession | undefined
  if (!session) {
    throw createError({ statusCode: 401, statusMessage: 'Sign in to continue' })
  }
  return session
}

export function requireLandlord(event: H3Event) {
  const session = requireSession(event)
  if (session.role !== 'landlord' && session.role !== 'agent') {
    throw createError({ statusCode: 403, statusMessage: 'Landlord access required' })
  }
  if (!session.landlordId) {
    throw createError({ statusCode: 403, statusMessage: 'Account is not linked to a landlord' })
  }
  return { ...session, landlordId: session.landlordId }
}

/**
 * Loads a tenancy but only when the caller is a party to it: the tenant on the
 * agreement, or someone acting for the landlord that owns it. Admins use the
 * back-office console, not this API, so they get the same 404 as a stranger.
 */
export async function assertTenancyAccess(event: H3Event, tenancyId: string) {
  const session = requireSession(event)
  const db = useDb()

  const scope =
    session.role === 'tenant'
      ? and(eq(tenancies.id, tenancyId), eq(tenancies.tenantId, session.userId))
      : and(eq(tenancies.id, tenancyId), eq(tenancies.landlordId, session.landlordId ?? ''))

  const [tenancy] = await db.select().from(tenancies).where(scope).limit(1)

  if (!tenancy) {
    throw createError({ statusCode: 404, statusMessage: 'Tenancy not found' })
  }

  return tenancy
}
