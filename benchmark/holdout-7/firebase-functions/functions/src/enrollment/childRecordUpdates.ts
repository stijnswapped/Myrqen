/**
 * Child record edits.
 *
 * Guardians keep the details on their own child up to date through the app (new
 * address, a new allergy, a changed doctor) and room staff correct things during the
 * enrolment interview.
 */
import { HttpsError, onCall } from "firebase-functions/v2/https";
import { DocumentData, FieldValue, getFirestore } from "firebase-admin/firestore";
import * as logger from "firebase-functions/logger";
import { Caller, CENTRE_STAFF_ROLES, requireCaller } from "../lib/authorization";

interface ChildRecordPatchRequest {
  childId?: string;
  patch?: Record<string, unknown>;
}

function assertMayEdit(caller: Caller, childId: string, child: DocumentData): void {
  const guardianUids: string[] = Array.isArray(child.guardianUids) ? child.guardianUids : [];
  const isLinkedGuardian = guardianUids.includes(caller.uid);
  const isOwnCentreStaff =
    CENTRE_STAFF_ROLES.includes(caller.role) && caller.centreId === child.centreId;

  if (!isLinkedGuardian && !isOwnCentreStaff) {
    logger.warn("child record edit blocked", { uid: caller.uid, childId });
    throw new HttpsError("permission-denied", "You cannot edit this child's record.");
  }
}

export const updateChildRecord = onCall<ChildRecordPatchRequest>(async (request) => {
  const caller = requireCaller(request);

  const childId = request.data?.childId;
  const patch = request.data?.patch;
  if (typeof childId !== "string" || childId.length === 0) {
    throw new HttpsError("invalid-argument", "childId is required.");
  }
  if (typeof patch !== "object" || patch === null || Array.isArray(patch)) {
    throw new HttpsError("invalid-argument", "patch must be an object.");
  }

  const db = getFirestore();
  const childRef = db.collection("children").doc(childId);
  const childSnap = await childRef.get();
  if (!childSnap.exists) {
    throw new HttpsError("not-found", "No child with that id.");
  }
  const child = childSnap.data() as DocumentData;

  assertMayEdit(caller, childId, child);

  // The profile form only submits the inputs it renders, so whatever arrives here is
  // already a subset of the editable fields and can be merged straight in. merge:true
  // keeps the fields the form did not touch.
  await childRef.set(
    {
      ...patch,
      updatedAt: FieldValue.serverTimestamp(),
      updatedBy: caller.uid,
    },
    { merge: true },
  );

  await db.collection("auditEvents").add({
    type: "child_record_updated",
    childId,
    actorUid: caller.uid,
    actorRole: caller.role,
    fields: Object.keys(patch),
    at: FieldValue.serverTimestamp(),
  });

  logger.info("child record updated", {
    uid: caller.uid,
    childId,
    fields: Object.keys(patch),
  });
  return { ok: true, updatedFields: Object.keys(patch).length };
});
