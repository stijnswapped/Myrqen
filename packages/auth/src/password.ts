import crypto from "node:crypto";

/**
 * Memory-hard password hashing using scrypt from the Node standard library.
 * Chosen over an external dependency so the POC has no native build step; the
 * stored format is versioned so parameters can be raised later.
 */
const SCRYPT = Object.freeze({ N: 32_768, r: 8, p: 2, keyLength: 64, saltBytes: 16 });
const PREFIX = "scrypt$1";
const MIN_PASSWORD_LENGTH = 12;
const MAX_PASSWORD_LENGTH = 200;

export class WeakPasswordError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WeakPasswordError";
  }
}

export function assertPasswordAcceptable(password: string): void {
  if (password.length < MIN_PASSWORD_LENGTH) {
    throw new WeakPasswordError(`Password must be at least ${MIN_PASSWORD_LENGTH} characters.`);
  }
  if (password.length > MAX_PASSWORD_LENGTH) {
    throw new WeakPasswordError(`Password must be at most ${MAX_PASSWORD_LENGTH} characters.`);
  }
  if (/^\s+$/.test(password)) throw new WeakPasswordError("Password cannot be only whitespace.");
}

function scrypt(password: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    crypto.scrypt(
      password.normalize("NFKC"),
      salt,
      SCRYPT.keyLength,
      { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, maxmem: 256 * 1024 * 1024 },
      (error, derived) => (error ? reject(error) : resolve(derived))
    );
  });
}

export async function hashPassword(password: string): Promise<string> {
  assertPasswordAcceptable(password);
  const salt = crypto.randomBytes(SCRYPT.saltBytes);
  const derived = await scrypt(password, salt);
  return [PREFIX, SCRYPT.N, SCRYPT.r, SCRYPT.p, salt.toString("base64url"), derived.toString("base64url")].join("$");
}

/**
 * A stored hash that no password can match, carrying the current parameters.
 * Verifying against it costs exactly what verifying a real account costs, which
 * is how a sign-in attempt for an address with no account avoids becoming a
 * timing oracle for which accounts exist.
 */
export function decoyPasswordHash(): string {
  const salt = crypto.randomBytes(SCRYPT.saltBytes);
  const unmatchable = crypto.randomBytes(SCRYPT.keyLength);
  return [PREFIX, SCRYPT.N, SCRYPT.r, SCRYPT.p, salt.toString("base64url"), unmatchable.toString("base64url")].join(
    "$"
  );
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split("$");
  if (parts.length !== 7 || parts[0] !== "scrypt" || parts[1] !== "1") return false;
  const N = Number(parts[2]);
  const r = Number(parts[3]);
  const p = Number(parts[4]);
  const salt = Buffer.from(parts[5] ?? "", "base64url");
  const expected = Buffer.from(parts[6] ?? "", "base64url");
  if (!Number.isInteger(N) || !Number.isInteger(r) || !Number.isInteger(p) || salt.length === 0) return false;

  const derived = await new Promise<Buffer>((resolve, reject) => {
    crypto.scrypt(
      password.normalize("NFKC"),
      salt,
      expected.length,
      { N, r, p, maxmem: 256 * 1024 * 1024 },
      (error, value) => (error ? reject(error) : resolve(value))
    );
  }).catch(() => null);

  if (!derived || derived.length !== expected.length) return false;
  return crypto.timingSafeEqual(derived, expected);
}
