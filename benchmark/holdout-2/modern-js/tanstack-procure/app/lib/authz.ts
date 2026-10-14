import { HttpError, type Role, type Session } from "./session";

/**
 * Role gate for the approval workflow. Kept out of the server functions so the
 * matrix lives in one place and can be reviewed on its own.
 */
export function requireRole(session: Session, ...allowed: Role[]): void {
  if (session.roles.includes("admin")) return;
  if (allowed.some((role) => session.roles.includes(role))) return;
  throw new HttpError(403, "You do not have permission to do that.");
}

/** Nobody signs off their own spend, whatever role they hold. */
export function refuseSelfApproval(session: Session, submittedById: string): void {
  if (session.userId === submittedById) {
    throw new HttpError(403, "A claim cannot be approved by the person who submitted it.");
  }
}
