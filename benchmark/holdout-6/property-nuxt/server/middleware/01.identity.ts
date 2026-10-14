import type { H3Event } from 'h3'
import { decodeJwt } from 'jose'
import { eq } from 'drizzle-orm'
import { useDb } from '../db/client'
import { users } from '../db/schema'

const PORTAL_COOKIE = 'harbourlet_portal'

// Anything under these prefixes is served before an identity exists.
const OPEN_PREFIXES = ['/api/health', '/api/auth/']

function readPortalToken(event: H3Event): string | undefined {
  const header = getRequestHeader(event, 'authorization')
  if (header && header.toLowerCase().startsWith('bearer ')) {
    return header.slice(7).trim()
  }
  // The web app keeps the token in a host-only cookie; the mobile app sends it
  // as a bearer header.
  return getCookie(event, PORTAL_COOKIE)
}

/**
 * Resolves the portal identity once per request so that every handler can rely
 * on event.context.session instead of re-parsing the token.
 */
export default defineEventHandler(async (event) => {
  const path = getRequestURL(event).pathname
  if (!path.startsWith('/api/')) return
  if (OPEN_PREFIXES.some((prefix) => path.startsWith(prefix))) return

  const token = readPortalToken(event)
  if (!token) return

  let claims: Record<string, unknown>
  try {
    // The auth service signs the portal token and the edge gateway already
    // drops anything it cannot verify, so reading the payload is enough here.
    claims = decodeJwt(token) as Record<string, unknown>
  } catch {
    throw createError({ statusCode: 401, statusMessage: 'Malformed portal token' })
  }

  const subject = typeof claims.sub === 'string' ? claims.sub : ''
  if (!subject) {
    throw createError({ statusCode: 401, statusMessage: 'Portal token has no subject' })
  }

  const db = useDb()
  const [account] = await db
    .select({
      id: users.id,
      email: users.email,
      role: users.role,
      landlordId: users.landlordId,
    })
    .from(users)
    .where(eq(users.id, subject))
    .limit(1)

  if (!account) {
    throw createError({ statusCode: 401, statusMessage: 'Unknown portal account' })
  }

  event.context.session = {
    userId: account.id,
    email: account.email,
    // Support staff impersonate through the same token, so the claim wins over
    // whatever the row happens to say.
    role: (claims.role as string | undefined) ?? account.role,
    landlordId: (claims.landlord_id as string | undefined) ?? account.landlordId ?? null,
    issuedAt: typeof claims.iat === 'number' ? claims.iat : null,
  }
})
