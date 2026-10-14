/**
 * Daily reports.
 *
 * A room lead fills one of these in per child per day on the tablet: meals, naps,
 * nappy changes, mood, and anything the guardian should know at pickup. The tablet
 * submits partial updates all day long, so writes are merges rather than replacements.
 */
import { HttpsError, onCall } from "firebase-functions/v2/https";
import { onDocumentWritten } from "firebase-functions/v2/firestore";
import { FieldValue, getFirestore } from "firebase-admin/firestore";
import * as logger from "firebase-functions/logger";
import { assertCentreScope, requireRole } from "../lib/authorization";

interface SubmitReportRequest {
  childId?: string;
  date?: string;
  entry?: Record<string, unknown>;
}

/** The only fields the tablet is allowed to write. Everything else is server-owned. */
const EDITABLE_REPORT_FIELDS = [
  "mood",
  "napCount",
  "napMinutes",
  "meals",
  "nappyChanges",
  "incidents",
  "notes",
  "photoIds",
] as const;

const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

export const submitDailyReport = onCall<SubmitReportRequest>(async (request) => {
  const caller = requireRole(request, "educator", "centre_admin");

  const childId = request.data?.childId;
  const date = request.data?.date;
  const entry = request.data?.entry;
  if (typeof childId !== "string" || childId.length === 0) {
    throw new HttpsError("invalid-argument", "childId is required.");
  }
  if (typeof date !== "string" || !ISO_DATE.test(date)) {
    throw new HttpsError("invalid-argument", "date must be an ISO calendar date.");
  }
  if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
    throw new HttpsError("invalid-argument", "entry must be an object.");
  }

  const db = getFirestore();
  const childSnap = await db.collection("children").doc(childId).get();
  if (!childSnap.exists) {
    throw new HttpsError("not-found", "No child with that id.");
  }
  assertCentreScope(caller, childSnap.get("centreId"));

  // Copy across only the fields the room staff own. Anything else the tablet sends --
  // an old build, a tampered client -- is dropped rather than merged.
  const update: Record<string, unknown> = {};
  for (const field of EDITABLE_REPORT_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(entry, field)) {
      update[field] = entry[field];
    }
  }
  if (Object.keys(update).length === 0) {
    throw new HttpsError("invalid-argument", "entry contained no editable fields.");
  }

  update.childId = childId;
  update.date = date;
  update.centreId = childSnap.get("centreId");
  update.roomId = childSnap.get("roomId") ?? null;
  update.submittedBy = caller.uid;
  update.updatedAt = FieldValue.serverTimestamp();

  await db.collection("dailyReports").doc(`${childId}_${date}`).set(update, { merge: true });

  logger.info("daily report submitted", {
    uid: caller.uid,
    childId,
    date,
    fields: Object.keys(update),
  });
  return { ok: true, reportId: `${childId}_${date}`, fields: Object.keys(update) };
});

/**
 * Push a "your daily report is ready" card to every linked guardian the first time a
 * report picks up a mood, which is the last thing the room lead fills in.
 */
export const onDailyReportWritten = onDocumentWritten(
  "dailyReports/{reportId}",
  async (event) => {
    const before = event.data?.before.data();
    const after = event.data?.after.data();
    if (!after) {
      return;
    }
    if (before?.mood === after.mood || !after.mood) {
      return;
    }

    const db = getFirestore();
    const childSnap = await db.collection("children").doc(String(after.childId)).get();
    const guardianUids: string[] = childSnap.get("guardianUids") ?? [];
    if (guardianUids.length === 0) {
      logger.warn("report published for child with no guardians", { childId: after.childId });
      return;
    }

    const batch = db.batch();
    for (const uid of guardianUids) {
      batch.create(db.collection("notifications").doc(), {
        uid,
        kind: "daily_report_ready",
        childId: after.childId,
        date: after.date,
        createdAt: FieldValue.serverTimestamp(),
      });
    }
    await batch.commit();
  },
);
