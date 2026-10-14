/**
 * Staff onboarding.
 *
 * A centre admin invites a colleague by email. If the person already has a Nestlings
 * login (some staff work across two centres in the same group) we attach the claims to
 * the existing account, otherwise we create one and let the reset-password mail act as
 * the invitation.
 */
import { HttpsError, onCall } from "firebase-functions/v2/https";
import { getAuth, UserRecord } from "firebase-admin/auth";
import { FieldValue, getFirestore } from "firebase-admin/firestore";
import * as logger from "firebase-functions/logger";
import { requireRole, Role } from "../lib/authorization";

interface InviteMemberRequest {
  email?: string;
  role?: string;
  jobTitle?: string;
  roomIds?: string[];
}

/** A centre admin may hand out these two roles and nothing else. */
const INVITABLE_ROLES: readonly Role[] = ["educator", "centre_admin"];

function normaliseRole(value: unknown): Role {
  if (typeof value !== "string" || !INVITABLE_ROLES.includes(value as Role)) {
    throw new HttpsError(
      "invalid-argument",
      `role must be one of: ${INVITABLE_ROLES.join(", ")}`,
    );
  }
  return value as Role;
}

async function findOrCreateUser(email: string): Promise<UserRecord> {
  try {
    return await getAuth().getUserByEmail(email);
  } catch (err) {
    if ((err as { code?: string }).code === "auth/user-not-found") {
      return await getAuth().createUser({ email, emailVerified: false });
    }
    throw err;
  }
}

export const inviteCentreMember = onCall<InviteMemberRequest>(async (request) => {
  const caller = requireRole(request, "centre_admin");

  const email = typeof request.data?.email === "string" ? request.data.email.trim().toLowerCase() : "";
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    throw new HttpsError("invalid-argument", "A valid email address is required.");
  }
  const role = normaliseRole(request.data?.role);

  // The centre is taken from the admin's own claims, never from the request, so an
  // admin of one centre cannot mint staff for another.
  const centreId = caller.centreId;
  if (!centreId) {
    throw new HttpsError("failed-precondition", "Your account is not attached to a centre.");
  }

  const user = await findOrCreateUser(email);
  const existing = user.customClaims ?? {};
  if (typeof existing.centreId === "string" && existing.centreId !== centreId) {
    throw new HttpsError(
      "already-exists",
      "That account already belongs to another centre. Ask support to move it.",
    );
  }

  await getAuth().setCustomUserClaims(user.uid, { ...existing, role, centreId });

  const db = getFirestore();
  const batch = db.batch();
  batch.set(
    db.collection("staffProfiles").doc(user.uid),
    {
      uid: user.uid,
      email,
      role,
      centreId,
      jobTitle: request.data?.jobTitle ?? null,
      roomIds: Array.isArray(request.data?.roomIds) ? request.data.roomIds : [],
      invitedBy: caller.uid,
      createdAt: FieldValue.serverTimestamp(),
    },
    { merge: true },
  );
  batch.create(db.collection("auditEvents").doc(), {
    type: "staff_invited",
    actorUid: caller.uid,
    targetUid: user.uid,
    role,
    centreId,
    at: FieldValue.serverTimestamp(),
  });
  await batch.commit();

  logger.info("staff member invited", { actor: caller.uid, target: user.uid, role, centreId });
  return { ok: true, uid: user.uid, role, centreId };
});
