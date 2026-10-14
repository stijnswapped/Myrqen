/**
 * Guardian-facing child summary.
 *
 * This is the endpoint the "who can collect my child" screen calls. It returns less
 * than the full profile but adds the pickup authorisations, which is why it lives
 * apart from enrollment/childProfiles.ts.
 */
import { HttpsError, onCall } from "firebase-functions/v2/https";
import { DocumentData, getFirestore } from "firebase-admin/firestore";
import * as logger from "firebase-functions/logger";
import { Caller, CENTRE_STAFF_ROLES, requireCaller } from "../lib/authorization";

interface ChildSummaryRequest {
  childId?: string;
}

const PICKUP_WINDOW = 30;

/**
 * A guardian may read a child they are linked to. Room staff and the centre admin may
 * read any child enrolled at their own centre. Nobody else may.
 */
function assertChildVisibleTo(caller: Caller, childId: string, child: DocumentData): void {
  const guardianUids: string[] = Array.isArray(child.guardianUids) ? child.guardianUids : [];
  const isLinkedGuardian = guardianUids.includes(caller.uid);
  const isOwnCentreStaff =
    CENTRE_STAFF_ROLES.includes(caller.role) && caller.centreId === child.centreId;

  if (!isLinkedGuardian && !isOwnCentreStaff) {
    logger.warn("child summary read blocked", {
      uid: caller.uid,
      role: caller.role,
      childId,
      childCentre: child.centreId ?? null,
    });
    throw new HttpsError("permission-denied", "You do not have access to this child.");
  }
}

export const getGuardianChildSummary = onCall<ChildSummaryRequest>(async (request) => {
  const caller = requireCaller(request);

  const childId = request.data?.childId;
  if (typeof childId !== "string" || childId.length === 0) {
    throw new HttpsError("invalid-argument", "childId is required.");
  }

  const db = getFirestore();
  const childSnap = await db.collection("children").doc(childId).get();
  if (!childSnap.exists) {
    throw new HttpsError("not-found", "No child with that id.");
  }
  const child = childSnap.data() as DocumentData;

  assertChildVisibleTo(caller, childId, child);

  const pickupSnap = await db
    .collection("pickupAuthorisations")
    .where("childId", "==", childId)
    .where("revoked", "==", false)
    .orderBy("createdAt", "desc")
    .limit(PICKUP_WINDOW)
    .get();

  logger.info("child summary served", { uid: caller.uid, childId });
  return {
    child: {
      id: childSnap.id,
      firstName: child.firstName,
      lastName: child.lastName,
      roomId: child.roomId ?? null,
      centreId: child.centreId,
      allergies: child.allergies ?? [],
    },
    pickupAuthorisations: pickupSnap.docs.map((doc) => ({
      id: doc.id,
      name: doc.get("name"),
      relationship: doc.get("relationship"),
      photoId: doc.get("photoId") ?? null,
    })),
  };
});
