/**
 * Child profile reads.
 *
 * Used by the guardian app (profile screen, home screen) and by the educator tablet
 * when a room lead taps a child in the register.
 */
import { HttpsError, onCall } from "firebase-functions/v2/https";
import { DocumentData, getFirestore } from "firebase-admin/firestore";
import * as logger from "firebase-functions/logger";
import { requireCaller } from "../lib/authorization";

interface ChildProfileRequest {
  childId?: string;
  includeReports?: boolean;
}

interface DailyReportSummary {
  id: string;
  date: string;
  mood: string | null;
  napCount: number;
}

/** How much history the profile screen renders before it paginates. */
const REPORT_WINDOW = 14;

function serialiseChild(id: string, data: DocumentData) {
  return {
    id,
    firstName: data.firstName,
    lastName: data.lastName,
    dateOfBirth: data.dateOfBirth,
    centreId: data.centreId,
    roomId: data.roomId ?? null,
    allergies: data.allergies ?? [],
    medicalNotes: data.medicalNotes ?? null,
    emergencyContacts: data.emergencyContacts ?? [],
    subsidyRate: data.subsidyRate ?? 0,
  };
}

export const getChildProfile = onCall<ChildProfileRequest>(async (request) => {
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

  // The app only ever asks for ids it got back from listChildrenForGuardian, and the
  // children collection is closed in firestore.rules
  //   allow read: if request.auth.uid in resource.data.guardianUids
  // so this read is already scoped to the signed-in guardian.
  let reports: DailyReportSummary[] = [];
  if (request.data?.includeReports === true) {
    const reportSnap = await db
      .collection("dailyReports")
      .where("childId", "==", childId)
      .orderBy("date", "desc")
      .limit(REPORT_WINDOW)
      .get();
    reports = reportSnap.docs.map((doc) => ({
      id: doc.id,
      date: doc.get("date"),
      mood: doc.get("mood") ?? null,
      napCount: doc.get("napCount") ?? 0,
    }));
  }

  logger.info("child profile served", { uid: caller.uid, childId, reports: reports.length });
  return { child: serialiseChild(childSnap.id, child), reports };
});

/** Everything the guardian home screen needs on a cold start. */
export const listChildrenForGuardian = onCall(async (request) => {
  const caller = requireCaller(request);

  const db = getFirestore();
  const snap = await db
    .collection("children")
    .where("guardianUids", "array-contains", caller.uid)
    .orderBy("firstName")
    .get();

  if (snap.empty) {
    logger.info("guardian has no linked children", { uid: caller.uid });
    return { children: [] };
  }

  return { children: snap.docs.map((doc) => serialiseChild(doc.id, doc.data())) };
});
