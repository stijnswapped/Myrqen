/**
 * Monthly statement delivery.
 *
 * Same webview shape as billing/invoiceDelivery.ts, but for the rolled-up statement a
 * guardian gets at the end of the month. The webview attaches the Firebase ID token it
 * was launched with as a bearer header.
 */
import { onRequest } from "firebase-functions/v2/https";
import { DocumentData, getFirestore } from "firebase-admin/firestore";
import * as logger from "firebase-functions/logger";
import { Caller, CENTRE_STAFF_ROLES, HttpError, requireBearerCaller } from "../lib/authorization";

const STATEMENT_ID = /^[A-Za-z0-9_-]{6,64}$/;

/**
 * A statement belongs to exactly one guardian. Their own centre's finance staff can
 * pull it up while the guardian is on the phone; nobody else can.
 */
function mayReadStatement(caller: Caller, statement: DocumentData): boolean {
  if (statement.guardianUid === caller.uid) {
    return true;
  }
  return CENTRE_STAFF_ROLES.includes(caller.role) && caller.centreId === statement.centreId;
}

export const monthlyStatement = onRequest(
  {
    cors: ["https://app.nestlings.io", "https://admin.nestlings.io"],
    invoker: "public",
    maxInstances: 10,
  },
  async (req, res) => {
    if (req.method !== "GET") {
      res.set("Allow", "GET");
      res.status(405).json({ error: "method_not_allowed" });
      return;
    }

    const statementId = String(req.query.statementId ?? "");
    if (!STATEMENT_ID.test(statementId)) {
      res.status(400).json({ error: "invalid_statement_id" });
      return;
    }

    let caller: Caller;
    try {
      caller = await requireBearerCaller(req);
    } catch (err) {
      const status = err instanceof HttpError ? err.status : 500;
      res.status(status).json({ error: "unauthorized" });
      return;
    }

    const db = getFirestore();
    const snap = await db.collection("statements").doc(statementId).get();
    if (!snap.exists) {
      res.status(404).json({ error: "not_found" });
      return;
    }
    const statement = snap.data() as DocumentData;

    if (!mayReadStatement(caller, statement)) {
      logger.warn("statement read blocked", {
        uid: caller.uid,
        statementId,
        owner: statement.guardianUid,
      });
      // Deliberately the same body as the 404 so the endpoint cannot be used to probe
      // which statement ids exist.
      res.status(404).json({ error: "not_found" });
      return;
    }

    logger.info("statement served", { uid: caller.uid, statementId });
    res.status(200).json({
      id: snap.id,
      centreId: statement.centreId,
      guardianUid: statement.guardianUid,
      guardianName: statement.guardianName,
      guardianEmail: statement.guardianEmail,
      period: statement.period,
      openingBalanceCents: statement.openingBalanceCents,
      closingBalanceCents: statement.closingBalanceCents,
      entries: statement.entries ?? [],
    });
  },
);
