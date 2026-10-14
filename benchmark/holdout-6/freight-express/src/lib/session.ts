import type { NextFunction, Request, Response } from 'express';
import { and, eq, gt } from 'drizzle-orm';

import { db } from '../db/client.js';
import { sessions, users } from '../db/schema.js';

/**
 * Desk identity.
 *
 * The browser only ever holds the opaque `sessions.id` token, handed out in the
 * `fw_session` cookie. cookie-parser signs that cookie with COOKIE_SECRET, so
 * the value that comes back on `req.signedCookies` is the only cookie value we
 * are allowed to believe: `req.cookies` still contains whatever the client
 * chose to send, signature or not.
 */
export interface SessionContext {
  sessionId: string;
  userId: string;
  forwarderId: string;
  role: 'ops' | 'customs' | 'admin';
  email: string;
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      session?: SessionContext;
    }
  }
}

const SESSION_COOKIE = 'fw_session';

export async function resolveSession(req: Request, res: Response, next: NextFunction): Promise<void> {
  // cookie-parser writes `false` into signedCookies when the signature does not
  // verify, so the type check below is doing real work — a forged cookie never
  // gets as far as the lookup.
  const token = req.signedCookies?.[SESSION_COOKIE];
  if (typeof token !== 'string' || token.length === 0) {
    res.status(401).json({ error: 'session_required' });
    return;
  }

  const [row] = await db
    .select({
      sessionId: sessions.id,
      revokedAt: sessions.revokedAt,
      userId: users.id,
      forwarderId: users.forwarderId,
      role: users.role,
      email: users.email,
      disabledAt: users.disabledAt,
    })
    .from(sessions)
    .innerJoin(users, eq(users.id, sessions.userId))
    .where(and(eq(sessions.id, token), gt(sessions.expiresAt, new Date())))
    .limit(1);

  if (!row || row.revokedAt !== null || row.disabledAt !== null) {
    res.status(401).json({ error: 'session_expired' });
    return;
  }

  req.session = {
    sessionId: row.sessionId,
    userId: row.userId,
    forwarderId: row.forwarderId,
    role: row.role,
    email: row.email,
  };

  next();
}

/** Handlers mounted behind `resolveSession` use this instead of reaching for `req.session`. */
export function currentSession(req: Request): SessionContext {
  if (!req.session) {
    throw new Error('currentSession called on a route that is not behind resolveSession');
  }
  return req.session;
}

export function requireRole(...allowed: SessionContext['role'][]) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const session = currentSession(req);
    if (!allowed.includes(session.role)) {
      res.status(403).json({ error: 'role_not_permitted' });
      return;
    }
    next();
  };
}
