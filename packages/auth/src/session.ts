import { randomToken, hashToken } from "./tokens.js";

export const SESSION_COOKIE = "myrqen_session";
export const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;

export interface NewSession {
  token: string;
  tokenHash: string;
  expiresAt: Date;
}

export function createSessionToken(now = new Date(), ttlMs = SESSION_TTL_MS): NewSession {
  const token = randomToken();
  return { token, tokenHash: hashToken(token), expiresAt: new Date(now.getTime() + ttlMs) };
}

export interface CookieOptions {
  httpOnly: true;
  sameSite: "lax";
  secure: boolean;
  path: "/";
  maxAge: number;
}

export function sessionCookieOptions(secure: boolean, ttlMs = SESSION_TTL_MS): CookieOptions {
  return { httpOnly: true, sameSite: "lax", secure, path: "/", maxAge: Math.floor(ttlMs / 1000) };
}

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

/**
 * Where a post-authentication redirect is allowed to go. A protocol-relative
 * '//evil.tld' and a '/\evil.tld' both begin with '/' yet a browser reads them
 * as absolute URLs, so a startsWith('/') test turns a sign-in link into an
 * off-site redirect the victim follows immediately after authenticating.
 * Control characters are stripped by browsers before parsing and can smuggle a
 * host past the same test, so they are refused too.
 */
export function safeRedirectPath(next: string, fallback: string): string {
  if (typeof next !== "string" || !next.startsWith("/")) return fallback;
  if (next.startsWith("//") || next.startsWith("/\\")) return fallback;
  if (/[\u0000-\u001f\u007f]/.test(next)) return fallback;
  return next;
}

export function isPlausibleEmail(email: string): boolean {
  const value = normalizeEmail(email);
  if (value.length < 5 || value.length > 254) return false;
  return /^[^\s@]+@[^\s@.]+(\.[^\s@.]+)+$/.test(value);
}
