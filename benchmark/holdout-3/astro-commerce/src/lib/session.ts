import { createHmac, timingSafeEqual } from "node:crypto";
import { eq } from "drizzle-orm";
import { db } from "./db/client";
import { customers, staff } from "./db/schema";

export const SESSION_COOKIE = "nv_session";
export const STAFF_COOKIE = "nv_staff";

/**
 * Session cookies are `<customerId>.<hmac>`. Keeping the signature check in one
 * place means middleware is the only code that has to get it right.
 */
export function sign(customerId: string): string {
  const mac = createHmac("sha256", import.meta.env.SESSION_SECRET).update(customerId).digest("base64url");
  return `${customerId}.${mac}`;
}

export function verify(value: string | undefined): string | null {
  if (!value) return null;
  const separator = value.lastIndexOf(".");
  if (separator <= 0) return null;

  const customerId = value.slice(0, separator);
  const presented = Buffer.from(value.slice(separator + 1), "base64url");
  const expected = Buffer.from(
    createHmac("sha256", import.meta.env.SESSION_SECRET).update(customerId).digest("base64url"),
    "base64url"
  );

  if (presented.length !== expected.length) return null;
  return timingSafeEqual(presented, expected) ? customerId : null;
}

export async function loadCustomer(customerId: string) {
  const [row] = await db
    .select({ id: customers.id, email: customers.email, displayName: customers.displayName })
    .from(customers)
    .where(eq(customers.id, customerId))
    .limit(1);
  return row ?? null;
}

export async function loadStaffRole(staffId: string) {
  const [row] = await db
    .select({ role: staff.role, disabledAt: staff.disabledAt })
    .from(staff)
    .where(eq(staff.id, staffId))
    .limit(1);
  if (!row || row.disabledAt) return null;
  return row.role as "support" | "merchandiser" | "admin";
}
