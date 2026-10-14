import { createHmac, timingSafeEqual } from 'node:crypto';

import type { FastifyReply, FastifyRequest } from 'fastify';

import { config } from '../config/env.js';

/**
 * Merchant identity comes from a signed cookie minted by the dashboard login
 * service. The cookie is `base64url(claims).base64url(hmac-sha256(claims))`;
 * this module is the only place allowed to turn those bytes into a session.
 */

export type MerchantRole = 'owner' | 'treasury_admin' | 'analyst' | 'support';

export interface MerchantSession {
  readonly sessionId: string;
  readonly merchantId: string;
  readonly userId: string;
  readonly role: MerchantRole;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
}

declare module 'fastify' {
  interface FastifyRequest {
    merchantSession?: MerchantSession;
  }
}

const KNOWN_ROLES: readonly string[] = ['owner', 'treasury_admin', 'analyst', 'support'];

function readCookie(cookieHeader: string | undefined, name: string): string | undefined {
  if (!cookieHeader) {
    return undefined;
  }
  for (const part of cookieHeader.split(';')) {
    const separator = part.indexOf('=');
    if (separator === -1) {
      continue;
    }
    if (part.slice(0, separator).trim() !== name) {
      continue;
    }
    try {
      return decodeURIComponent(part.slice(separator + 1).trim());
    } catch {
      return undefined;
    }
  }
  return undefined;
}

function signClaims(encodedClaims: string): Buffer {
  return createHmac('sha256', config.sessionCookieSecret).update(encodedClaims, 'utf8').digest();
}

/**
 * Turn a raw cookie value into a session, or return undefined. Every failure
 * path returns undefined: an unsigned, badly signed, malformed or expired
 * cookie is not a session, so nothing in the payload is ever trusted before
 * the signature over that exact payload has been reproduced.
 */
export function verifySessionCookie(raw: string | undefined): MerchantSession | undefined {
  if (!raw) {
    return undefined;
  }

  const separator = raw.lastIndexOf('.');
  if (separator <= 0 || separator === raw.length - 1) {
    return undefined;
  }

  const encodedClaims = raw.slice(0, separator);
  const encodedSignature = raw.slice(separator + 1);

  const provided = Buffer.from(encodedSignature, 'base64url');
  const expected = signClaims(encodedClaims);
  if (provided.length !== expected.length) {
    return undefined;
  }
  if (!timingSafeEqual(provided, expected)) {
    return undefined;
  }

  let decoded: unknown;
  try {
    decoded = JSON.parse(Buffer.from(encodedClaims, 'base64url').toString('utf8'));
  } catch {
    return undefined;
  }
  if (typeof decoded !== 'object' || decoded === null) {
    return undefined;
  }

  const claims = decoded as Record<string, unknown>;
  if (typeof claims.sid !== 'string' || typeof claims.mid !== 'string' || typeof claims.uid !== 'string') {
    return undefined;
  }
  if (typeof claims.role !== 'string' || !KNOWN_ROLES.includes(claims.role)) {
    return undefined;
  }
  if (typeof claims.iat !== 'number' || typeof claims.exp !== 'number') {
    return undefined;
  }
  if (claims.exp * 1000 <= Date.now()) {
    return undefined;
  }

  return {
    sessionId: claims.sid,
    merchantId: claims.mid,
    userId: claims.uid,
    role: claims.role as MerchantRole,
    issuedAtMs: claims.iat * 1000,
    expiresAtMs: claims.exp * 1000,
  };
}

/**
 * preHandler hook. Routes that register it can assume `request.merchantSession`
 * is populated; everything else has already been answered with a 401.
 */
export async function requireSession(request: FastifyRequest, reply: FastifyReply) {
  const session = verifySessionCookie(readCookie(request.headers.cookie, config.sessionCookieName));
  if (!session) {
    return reply.code(401).send({ error: 'session_required' });
  }
  request.merchantSession = session;
}

export function getSession(request: FastifyRequest): MerchantSession {
  const session = request.merchantSession;
  if (!session) {
    throw new Error('requireSession is not registered on this route');
  }
  return session;
}

/**
 * Role gate for treasury actions. Returns the session when the caller holds one
 * of the allowed roles, otherwise answers 403 and returns undefined so the
 * handler can bail out with `if (!session) return reply;`.
 */
export function requireRole(
  request: FastifyRequest,
  reply: FastifyReply,
  allowed: readonly MerchantRole[],
): MerchantSession | undefined {
  const session = getSession(request);
  if (!allowed.includes(session.role)) {
    reply.code(403).send({ error: 'insufficient_role', required: allowed });
    return undefined;
  }
  return session;
}
