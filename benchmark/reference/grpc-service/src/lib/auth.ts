import * as grpc from '@grpc/grpc-js'
import jwt, { type JwtPayload } from 'jsonwebtoken'

/**
 * Caller identity for depot.v1.DepotService.
 *
 * Every call carries a platform access token in the `authorization`
 * metadata header — the storefront BFF, the warehouse terminals and the
 * batch workers all get one from the auth service. The signing secret is
 * mounted by the platform chart and rotated weekly, so tokens minted
 * before a rotation stop verifying and the caller re-authenticates.
 */

export type StaffRole =
  | 'storefront'
  | 'warehouse_ops'
  | 'inventory_manager'
  | 'finance'
  | 'internal'

const KNOWN_ROLES: readonly StaffRole[] = [
  'storefront',
  'warehouse_ops',
  'inventory_manager',
  'finance',
  'internal',
]

/** Roles that are deliberately not pinned to a depot list. */
const DEPOT_UNRESTRICTED_ROLES: readonly StaffRole[] = ['finance', 'internal']

const TOKEN_ISSUER = 'https://auth.platform.internal/'
const TOKEN_AUDIENCE = 'depot.v1.DepotService'
const CLOCK_TOLERANCE_SECONDS = 5

export interface Claims {
  subject: string
  role: StaffRole
  /** Depots the caller is scoped to. Empty for the unrestricted roles. */
  depotIds: string[]
  tokenId: string
}

export class RpcStatusError extends Error {
  constructor(
    readonly code: grpc.status,
    message: string,
  ) {
    super(message)
    this.name = 'RpcStatusError'
  }
}

/**
 * Turn a thrown error into something a unary callback can send. Only the
 * statuses we raised ourselves keep their message; anything else is our
 * bug, not the caller's business, so the detail stays in the pod logs.
 */
export function asServiceError(err: unknown): { code: grpc.status; message: string } {
  if (err instanceof RpcStatusError) {
    return { code: err.code, message: err.message }
  }
  console.error('[depot] unhandled handler error', err)
  return { code: grpc.status.INTERNAL, message: 'internal error' }
}

function signingSecret(): string {
  const secret = process.env.DEPOT_TOKEN_SECRET
  if (!secret) {
    // Fail closed. A missing secret must not degrade into "nobody is
    // authenticated, so everybody is allowed".
    throw new RpcStatusError(grpc.status.INTERNAL, 'token signing secret is not configured')
  }
  return secret
}

function bearerToken(metadata: grpc.Metadata): string {
  const [header] = metadata.get('authorization')
  if (typeof header !== 'string' || header.length === 0) {
    throw new RpcStatusError(grpc.status.UNAUTHENTICATED, 'authorization metadata is missing')
  }
  const match = /^Bearer\s+(\S+)$/i.exec(header.trim())
  if (!match) {
    throw new RpcStatusError(
      grpc.status.UNAUTHENTICATED,
      'authorization metadata is not a bearer token',
    )
  }
  return match[1]
}

export function claimsFrom(metadata: grpc.Metadata): Claims {
  const token = bearerToken(metadata)

  let payload: JwtPayload
  try {
    payload = jwt.verify(token, signingSecret(), {
      algorithms: ['HS256'],
      issuer: TOKEN_ISSUER,
      audience: TOKEN_AUDIENCE,
      clockTolerance: CLOCK_TOLERANCE_SECONDS,
    }) as JwtPayload
  } catch {
    // Expired, wrong issuer, wrong algorithm, forged signature: the caller
    // gets the same answer for all of them.
    throw new RpcStatusError(grpc.status.UNAUTHENTICATED, 'access token rejected')
  }

  const subject = typeof payload.sub === 'string' ? payload.sub : ''
  const role = payload.role as StaffRole
  if (subject.length === 0 || !KNOWN_ROLES.includes(role)) {
    throw new RpcStatusError(grpc.status.UNAUTHENTICATED, 'access token has no usable sub or role')
  }

  const depotIds = Array.isArray(payload.depot_ids)
    ? payload.depot_ids.filter((id: unknown): id is string => typeof id === 'string')
    : []

  return {
    subject,
    role,
    depotIds,
    tokenId: typeof payload.jti === 'string' ? payload.jti : '',
  }
}

export function requireRole(claims: Claims, ...allowed: StaffRole[]): void {
  if (!allowed.includes(claims.role)) {
    throw new RpcStatusError(
      grpc.status.PERMISSION_DENIED,
      `role ${claims.role} may not call this method`,
    )
  }
}

/**
 * Depot-scoped roles may only touch depots named in their token. An empty
 * depot id is not "any depot": protobuf hands us '' for a field the caller
 * never set, so reject it rather than letting it match nothing quietly.
 */
export function assertDepotAccess(claims: Claims, depotId: string): void {
  if (depotId.length === 0) {
    throw new RpcStatusError(grpc.status.INVALID_ARGUMENT, 'depot_id is required')
  }
  if (DEPOT_UNRESTRICTED_ROLES.includes(claims.role)) return
  if (!claims.depotIds.includes(depotId)) {
    throw new RpcStatusError(grpc.status.PERMISSION_DENIED, 'caller is not scoped to that depot')
  }
}
