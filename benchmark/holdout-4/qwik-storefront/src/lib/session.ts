import type { Cookie, RequestEventCommon } from '@builder.io/qwik-city';
import { createHmac, timingSafeEqual } from 'node:crypto';

export const SESSION_COOKIE = 'vs_session';

const SESSION_TTL_MS = 1000 * 60 * 60 * 12;

export type StoreRole = 'customer' | 'support_agent' | 'admin';

export type StoreSession = {
  customerId: string;
  email: string;
  role: StoreRole;
  /** Set while a support agent is acting on a customer's behalf. */
  impersonatedBy?: string;
  issuedAt: number;
};

function signingKey(): string {
  const key = process.env.SESSION_SIGNING_KEY;
  if (!key) {
    throw new Error('SESSION_SIGNING_KEY must be set before the storefront boots');
  }
  return key;
}

function sign(payload: string): string {
  return createHmac('sha256', signingKey()).update(payload).digest('base64url');
}

/** Returns the session carried by the cookie, or null when it is absent, tampered with or stale. */
export function readSession(cookie: Cookie): StoreSession | null {
  const raw = cookie.get(SESSION_COOKIE)?.value;
  if (!raw) {
    return null;
  }

  const [payload, signature] = raw.split('.');
  if (!payload || !signature) {
    return null;
  }

  const expected = Buffer.from(sign(payload));
  const provided = Buffer.from(signature);
  if (expected.length !== provided.length || !timingSafeEqual(expected, provided)) {
    return null;
  }

  try {
    const session = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as StoreSession;
    return Date.now() - session.issuedAt > SESSION_TTL_MS ? null : session;
  } catch {
    return null;
  }
}

export function writeSession(cookie: Cookie, session: StoreSession): void {
  const payload = Buffer.from(JSON.stringify(session), 'utf8').toString('base64url');
  cookie.set(SESSION_COOKIE, `${payload}.${sign(payload)}`, {
    path: '/',
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    maxAge: SESSION_TTL_MS / 1000,
  });
}

/** Loader/action guard: 401s when the caller has no valid session cookie. */
export function requireSession(event: RequestEventCommon): StoreSession {
  const session = readSession(event.cookie);
  if (!session) {
    throw event.error(401, 'Sign in to continue');
  }
  return session;
}

export function isSupportAgent(session: StoreSession): boolean {
  return session.role === 'support_agent' || session.role === 'admin';
}
