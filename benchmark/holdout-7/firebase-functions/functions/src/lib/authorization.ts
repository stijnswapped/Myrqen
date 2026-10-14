/**
 * Caller identity for the Nestlings platform.
 *
 * Every deployed function resolves "who is asking" through this module, so there is
 * one definition of it for callables (Firebase Auth context attached to the request)
 * and one for plain HTTP endpoints (a bearer ID token in the Authorization header).
 *
 * Roles and the centre a member of staff belongs to live in custom claims, written by
 * staff/staffOnboarding.ts. The client refreshes its ID token after a role change, so
 * within a single request token.centreId can be treated as authoritative.
 */
import { getAuth } from "firebase-admin/auth";
import { CallableRequest, HttpsError, Request } from "firebase-functions/v2/https";
import * as logger from "firebase-functions/logger";

export type Role = "guardian" | "educator" | "centre_admin" | "platform_support";

/** Roles that are scoped to exactly one centre. */
export const CENTRE_STAFF_ROLES: readonly Role[] = ["educator", "centre_admin"];

export interface Caller {
  uid: string;
  email: string | null;
  role: Role;
  centreId: string | null;
}

/** Thrown by the HTTP helpers below; handlers turn it into a status code. */
export class HttpError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
    this.name = "HttpError";
  }
}

function toCaller(uid: string, token: Record<string, unknown>): Caller {
  // Anyone who signs up through the guardian app starts with no role claim at all.
  const role = typeof token.role === "string" ? (token.role as Role) : "guardian";
  return {
    uid,
    email: typeof token.email === "string" ? token.email : null,
    role,
    centreId: typeof token.centreId === "string" ? token.centreId : null,
  };
}

/** Resolve the caller of a callable function, or reject the call. */
export function requireCaller(request: CallableRequest<unknown>): Caller {
  if (!request.auth) {
    throw new HttpsError("unauthenticated", "Sign in to continue.");
  }
  return toCaller(request.auth.uid, request.auth.token as unknown as Record<string, unknown>);
}

/** Resolve the caller and assert they hold one of the given roles. */
export function requireRole(request: CallableRequest<unknown>, ...allowed: Role[]): Caller {
  const caller = requireCaller(request);
  if (!allowed.includes(caller.role)) {
    logger.warn("role check failed", { uid: caller.uid, role: caller.role, allowed });
    throw new HttpsError("permission-denied", "Your account cannot perform this action.");
  }
  return caller;
}

/**
 * Assert the caller belongs to the centre that owns a record. Platform support works
 * across every centre, which is why their sessions are short-lived and audited.
 */
export function assertCentreScope(caller: Caller, centreId: string | undefined | null): void {
  if (caller.role === "platform_support") {
    return;
  }
  if (!centreId || caller.centreId !== centreId) {
    logger.warn("centre scope check failed", {
      uid: caller.uid,
      callerCentre: caller.centreId,
      recordCentre: centreId ?? null,
    });
    throw new HttpsError("permission-denied", "That record belongs to another centre.");
  }
}

/** Resolve the caller of an HTTP function from its bearer ID token. */
export async function requireBearerCaller(req: Request): Promise<Caller> {
  const header = req.header("authorization") ?? "";
  const [scheme, token] = header.split(" ");
  if (!/^bearer$/i.test(scheme ?? "") || !token) {
    throw new HttpError(401, "A bearer ID token is required.");
  }
  try {
    // checkRevoked, so a guardian we removed from a centre this morning cannot keep
    // pulling documents with an hour-old token.
    const decoded = await getAuth().verifyIdToken(token, true);
    return toCaller(decoded.uid, decoded as unknown as Record<string, unknown>);
  } catch (err) {
    logger.warn("id token rejected", { reason: (err as Error).message });
    throw new HttpError(401, "Your session has expired. Sign in again.");
  }
}
