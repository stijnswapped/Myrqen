import crypto from "node:crypto";
import { BRAND } from "@myrqen/brand";

const TOKEN_BYTES = 32;

export function randomToken(bytes = TOKEN_BYTES): string {
  return crypto.randomBytes(bytes).toString("base64url");
}

/** Server stores only this digest. A database read cannot mint a credential. */
export function hashToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("base64url");
}

export function timingSafeEqualStrings(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

export interface DeviceCredential {
  keyId: string;
  secret: string;
  /** The single string handed to the CLI, shown exactly once. */
  token: string;
}

/**
 * Device token layout: `<prefix><keyId>.<secret>`. The key id lets the server
 * look up one row and compare a hash without scanning, and enables per-device
 * revocation and rotation.
 */
export function createDeviceCredential(prefix = BRAND.deviceTokenPrefix): DeviceCredential {
  const keyId = crypto.randomBytes(9).toString("base64url");
  const secret = randomToken();
  return { keyId, secret, token: `${prefix}${keyId}.${secret}` };
}

export function parseDeviceToken(
  token: string,
  prefix = BRAND.deviceTokenPrefix
): { keyId: string; secret: string } | null {
  if (!token.startsWith(prefix)) return null;
  const body = token.slice(prefix.length);
  const separator = body.indexOf(".");
  if (separator <= 0) return null;
  const keyId = body.slice(0, separator);
  const secret = body.slice(separator + 1);
  if (!keyId || !secret) return null;
  return { keyId, secret };
}

export function deviceSecretHash(secret: string): string {
  return hashToken(secret);
}

/** Opaque, high-entropy public identifiers for device link requests. */
export function createLinkRequestIdentifiers(): { publicRequestId: string; verifier: string; verifierHash: string } {
  const verifier = randomToken(32);
  return {
    publicRequestId: `req_${crypto.randomBytes(16).toString("base64url")}`,
    verifier,
    verifierHash: hashToken(verifier)
  };
}

export function shareSlug(): { slug: string; slugHash: string } {
  const slug = crypto.randomBytes(16).toString("base64url");
  return { slug, slugHash: hashToken(slug) };
}
