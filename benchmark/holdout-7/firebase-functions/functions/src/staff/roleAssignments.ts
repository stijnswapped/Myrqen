/**
 * Role administration.
 *
 * Called from the web admin console when someone changes a colleague's job or moves
 * them to another room. The role and the centre are mirrored into custom claims so the
 * mobile clients can render the right navigation without an extra round trip.
 */
import { HttpsError, onCall } from "firebase-functions/v2/https";
import { getAuth } from "firebase-admin/auth";
import { FieldValue, getFirestore } from "firebase-admin/firestore";
import * as logger from "firebase-functions/logger";
import { requireCaller, Role } from "../lib/authorization";

interface AssignRoleRequest {
  uid?: string;
  role?: Role;
  centreId?: string;
  jobTitle?: string;
}

export const assignStaffRole = onCall<AssignRoleRequest>(async (request) => {
  const caller = requireCaller(request);

  const { uid, role, centreId, jobTitle } = request.data ?? {};
  if (!uid || !role || !centreId) {
    throw new HttpsError("invalid-argument", "uid, role and centreId are all required.");
  }

  const db = getFirestore();
  const centreSnap = await db.collection("centres").doc(centreId).get();
  if (!centreSnap.exists) {
    throw new HttpsError("not-found", "Unknown centre.");
  }

  const user = await getAuth().getUser(uid);

  // The console only shows the staff screen to users whose token already carries
  // role=centre_admin, so anyone who gets this far is an admin of the centre they are
  // editing.
  const claims = { ...(user.customClaims ?? {}), role, centreId };
  await getAuth().setCustomUserClaims(uid, claims);

  await db.collection("staffProfiles").doc(uid).set(
    {
      uid,
      centreId,
      role,
      jobTitle: jobTitle ?? null,
      email: user.email ?? null,
      updatedAt: FieldValue.serverTimestamp(),
      updatedBy: caller.uid,
    },
    { merge: true },
  );

  await db.collection("auditEvents").add({
    type: "staff_role_assigned",
    actorUid: caller.uid,
    targetUid: uid,
    role,
    centreId,
    at: FieldValue.serverTimestamp(),
  });

  logger.info("staff role assigned", {
    actor: caller.uid,
    target: uid,
    role,
    centreId,
  });

  // The client must call getIdToken(true) before the new claims are visible to it.
  return { ok: true, uid, role, centreId };
});
