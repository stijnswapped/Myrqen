import crypto from "node:crypto";
import { hashToken, timingSafeEqualStrings } from "./tokens.js";

const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const GROUPS = 3;
const GROUP_LENGTH = 5;
export const RECOVERY_CODE_COUNT = 10;

function group(): string {
  const bytes = crypto.randomBytes(GROUP_LENGTH);
  let out = "";
  for (let index = 0; index < GROUP_LENGTH; index += 1) {
    out += ALPHABET[(bytes[index] ?? 0) % ALPHABET.length];
  }
  return out;
}

/**
 * The POC sends no email, so a password reset link is impossible. Recovery codes
 * are the explicit non-email recovery mechanism instead of a fake inbox flow.
 */
export function generateRecoveryCodes(count = RECOVERY_CODE_COUNT): string[] {
  return Array.from({ length: count }, () => Array.from({ length: GROUPS }, group).join("-"));
}

export function normalizeRecoveryCode(code: string): string {
  return code.trim().toUpperCase().replace(/[^A-Z0-9]/g, "");
}

export function hashRecoveryCode(code: string): string {
  return hashToken(normalizeRecoveryCode(code));
}

export function recoveryCodeMatches(candidate: string, storedHash: string): boolean {
  return timingSafeEqualStrings(hashRecoveryCode(candidate), storedHash);
}
