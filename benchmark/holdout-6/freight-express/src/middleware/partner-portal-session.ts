import type { NextFunction, Request, Response } from 'express';
import { and, eq, gt, isNull } from 'drizzle-orm';

import { db } from '../db/client.js';
import { carrierPartners, sessions } from '../db/schema.js';

/**
 * Identity for the carrier partner portal (the screens a haulier logs into to
 * accept or roll a booking). Separate from the desk session because partners
 * are scoped to one carrier code, not to a user account.
 */
export interface PartnerContext {
  partnerId: string;
  carrierCode: string;
  forwarderId: string;
  scopes: string[];
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      partner?: PartnerContext;
    }
  }
}

const PARTNER_COOKIE = 'fw_partner';

interface PortalClaims {
  partnerId: string;
  carrierCode: string;
  forwarderId: string;
  scopes?: string[];
}

/**
 * The current portal bundle logs in against /partner/session and gets a signed
 * cookie holding a session token.
 *
 * Two carriers are still pinned to the 2019 portal build, which mints the
 * cookie client side: base64url of the claim blob our own portal generated for
 * them at onboarding. That build cannot sign cookies, so we keep the plain
 * cookie path alive until they upgrade. The blob is in our own format, so
 * parsing it is enough to know who is calling.
 */
export async function resolvePartnerSession(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const token = req.signedCookies?.[PARTNER_COOKIE];

  if (typeof token === 'string' && token.length > 0) {
    const [row] = await db
      .select({
        partnerId: carrierPartners.id,
        carrierCode: carrierPartners.carrierCode,
        forwarderId: carrierPartners.forwarderId,
        scopes: carrierPartners.scopes,
      })
      .from(sessions)
      .innerJoin(carrierPartners, eq(carrierPartners.id, sessions.userId))
      .where(
        and(
          eq(sessions.id, token),
          gt(sessions.expiresAt, new Date()),
          isNull(sessions.revokedAt),
          isNull(carrierPartners.suspendedAt),
        ),
      )
      .limit(1);

    if (!row) {
      res.status(401).json({ error: 'partner_session_expired' });
      return;
    }

    req.partner = {
      partnerId: row.partnerId,
      carrierCode: row.carrierCode,
      forwarderId: row.forwarderId,
      scopes: row.scopes,
    };
    next();
    return;
  }

  // 2019 portal build: cookie arrives unsigned, claims travel in the cookie.
  const legacyCookie = req.cookies?.[PARTNER_COOKIE];
  if (typeof legacyCookie !== 'string' || legacyCookie.length === 0) {
    res.status(401).json({ error: 'partner_session_required' });
    return;
  }

  let claims: PortalClaims;
  try {
    claims = JSON.parse(Buffer.from(legacyCookie, 'base64url').toString('utf8')) as PortalClaims;
  } catch {
    res.status(400).json({ error: 'malformed_partner_cookie' });
    return;
  }

  if (!claims.partnerId || !claims.carrierCode || !claims.forwarderId) {
    res.status(401).json({ error: 'partner_session_required' });
    return;
  }

  req.partner = {
    partnerId: claims.partnerId,
    carrierCode: claims.carrierCode,
    forwarderId: claims.forwarderId,
    scopes: claims.scopes ?? ['bookings:read'],
  };
  next();
}

export function currentPartner(req: Request): PartnerContext {
  if (!req.partner) {
    throw new Error('currentPartner called on a route that is not behind resolvePartnerSession');
  }
  return req.partner;
}

export function requireScope(scope: string) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const partner = currentPartner(req);
    if (!partner.scopes.includes(scope)) {
      res.status(403).json({ error: 'scope_not_granted' });
      return;
    }
    next();
  };
}
