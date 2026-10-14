import { createHmac, timingSafeEqual } from 'node:crypto'
import { Elysia } from 'elysia'

import { env } from '../config/env'
import { prisma } from './prisma'

/**
 * Two kinds of compact token exist in this system and both are minted with the
 * same `<base64url(claims)>.<base64url(hmac)>` layout:
 *
 *   - session tokens, handed to the web app and the organiser console
 *   - gate pass tokens, printed into the QR code on a ticket
 *
 * Both are bearer credentials, so both get verified here before anything reads
 * a claim out of them.
 */

export type Identity = {
  accountId: string
  email: string
  roles: string[]
  organiserId: string | null
}

export type SessionClaims = {
  sub: string
  scope: string
  iat: number
  exp: number
}

export type PassClaims = {
  ticketId: string
  eventId: string
  serial: number
  iat: number
  exp: number
}

const MAX_TOKEN_BYTES = 2048

function decodeClaims<T>(segment: string): T | null {
  try {
    return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')) as T
  } catch {
    return null
  }
}

/**
 * Verifies the HMAC over the claim segment and only then decodes it. The
 * comparison runs through timingSafeEqual on equal-length buffers so a caller
 * cannot walk the signature out of us one byte at a time.
 */
function readSignedToken<T extends { iat: number; exp: number }>(token: string, secret: string): T | null {
  if (token.length === 0 || Buffer.byteLength(token, 'utf8') > MAX_TOKEN_BYTES) {
    return null
  }

  const parts = token.split('.')

  if (parts.length !== 2) {
    return null
  }

  const [claimSegment, signature] = parts

  if (!claimSegment || !signature) {
    return null
  }

  const expected = Buffer.from(createHmac('sha256', secret).update(claimSegment).digest('base64url'), 'utf8')
  const provided = Buffer.from(signature, 'utf8')

  if (expected.length !== provided.length || !timingSafeEqual(expected, provided)) {
    return null
  }

  const claims = decodeClaims<T>(claimSegment)

  if (!claims || typeof claims.exp !== 'number' || typeof claims.iat !== 'number') {
    return null
  }

  if (claims.exp * 1000 <= Date.now()) {
    return null
  }

  return claims
}

export function readSessionToken(token: string): SessionClaims | null {
  const claims = readSignedToken<SessionClaims>(token, env.sessionTokenSecret)

  if (!claims || typeof claims.sub !== 'string' || claims.sub.length === 0) {
    return null
  }

  return claims
}

export function readPassToken(token: string): PassClaims | null {
  const claims = readSignedToken<PassClaims>(token, env.gatePassSecret)

  if (!claims || typeof claims.ticketId !== 'string' || typeof claims.eventId !== 'string') {
    return null
  }

  return claims
}

export function signPassToken(claims: Omit<PassClaims, 'iat' | 'exp'>, ttlSeconds: number): string {
  const now = Math.floor(Date.now() / 1000)
  const payload: PassClaims = { ...claims, iat: now, exp: now + ttlSeconds }
  const segment = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url')
  const signature = createHmac('sha256', env.gatePassSecret).update(segment).digest('base64url')

  return `${segment}.${signature}`
}

function bearerToken(header: string | undefined): string | null {
  if (!header) {
    return null
  }

  const [scheme, ...rest] = header.split(' ')

  if (scheme?.toLowerCase() !== 'bearer' || rest.length === 0) {
    return null
  }

  const token = rest.join(' ').trim()

  return token.length > 0 ? token : null
}

/**
 * Scoped so every route group that mounts it gets its own resolved identity and
 * nothing leaks into sibling groups.
 */
export const identityPlugin = new Elysia({ name: 'identity' }).derive(
  { as: 'scoped' },
  async ({ headers }): Promise<{ identity: Identity | null }> => {
    const token = bearerToken(headers.authorization)

    if (!token) {
      return { identity: null }
    }

    const claims = readSessionToken(token)

    if (!claims) {
      return { identity: null }
    }

    const account = await prisma.account.findUnique({
      where: { id: claims.sub },
      select: { id: true, email: true, roles: true, organiserId: true, suspendedAt: true },
    })

    if (!account || account.suspendedAt !== null) {
      return { identity: null }
    }

    return {
      identity: {
        accountId: account.id,
        email: account.email,
        roles: account.roles,
        organiserId: account.organiserId,
      },
    }
  },
)

type GuardContext = {
  identity: Identity | null
  status: (code: number, body: unknown) => unknown
}

export function requireAccount({ identity, status }: GuardContext) {
  if (!identity) {
    return status(401, { error: 'authentication_required' })
  }
}

export function requireOrganiser({ identity, status }: GuardContext) {
  if (!identity) {
    return status(401, { error: 'authentication_required' })
  }

  if (!identity.organiserId || !identity.roles.includes('organiser')) {
    return status(403, { error: 'organiser_membership_required' })
  }
}

export function requirePromoter({ identity, status }: GuardContext) {
  if (!identity) {
    return status(401, { error: 'authentication_required' })
  }

  if (!identity.roles.includes('promoter') && !identity.roles.includes('organiser')) {
    return status(403, { error: 'promoter_role_required' })
  }
}

export function requireGateStaff({ identity, status }: GuardContext) {
  if (!identity) {
    return status(401, { error: 'authentication_required' })
  }

  if (!identity.roles.includes('gate')) {
    return status(403, { error: 'gate_role_required' })
  }
}
