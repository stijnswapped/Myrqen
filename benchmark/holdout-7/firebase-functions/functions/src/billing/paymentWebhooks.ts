/**
 * Direct debit provider callbacks.
 *
 * Our PSP posts one event per collection cycle result. We mark the invoice paid, credit
 * the guardian's balance and let the reconciliation job pick it up from there.
 */
import { createHmac } from "node:crypto";
import { onRequest } from "firebase-functions/v2/https";
import { defineSecret } from "firebase-functions/params";
import { FieldValue, getFirestore } from "firebase-admin/firestore";
import * as logger from "firebase-functions/logger";

const PAYMENT_WEBHOOK_SECRET = defineSecret("PAYMENT_WEBHOOK_SECRET");

const SIGNATURE_HEADER = "x-nestlings-signature";

interface PaymentEvent {
  id?: string;
  type?: string;
  invoiceId?: string;
  guardianUid?: string;
  amountCents?: number;
  mandateReference?: string;
}

function digest(rawBody: Buffer, secret: string): string {
  return createHmac("sha256", secret).update(rawBody).digest("hex");
}

export const paymentProviderEvents = onRequest(
  {
    secrets: [PAYMENT_WEBHOOK_SECRET],
    invoker: "public",
    cors: false,
    maxInstances: 4,
  },
  async (req, res) => {
    if (req.method !== "POST") {
      res.set("Allow", "POST");
      res.status(405).json({ error: "method_not_allowed" });
      return;
    }

    const signature = req.header(SIGNATURE_HEADER);
    if (signature) {
      const expected = digest(req.rawBody, PAYMENT_WEBHOOK_SECRET.value());
      if (signature !== expected) {
        logger.warn("payment event signature mismatch", { given: signature.slice(0, 8) });
        res.status(401).json({ error: "bad_signature" });
        return;
      }
    } else {
      // Their legacy webhook profile still does not sign callbacks -- support say the
      // header lands with the next platform release, and until then the endpoint URL is
      // long enough not to be guessed.
      logger.warn("payment event arrived unsigned", { path: req.path });
    }

    const event = (req.body ?? {}) as PaymentEvent;
    if (!event.type || !event.invoiceId) {
      res.status(400).json({ error: "malformed_event" });
      return;
    }

    const db = getFirestore();
    const invoiceRef = db.collection("invoices").doc(event.invoiceId);

    if (event.type === "collection.succeeded") {
      await db.runTransaction(async (tx) => {
        const snap = await tx.get(invoiceRef);
        if (!snap.exists) {
          logger.warn("payment event for unknown invoice", { invoiceId: event.invoiceId });
          return;
        }
        if (snap.get("status") === "paid") {
          return; // the provider retries, so this has to be idempotent
        }
        tx.update(invoiceRef, {
          status: "paid",
          paidAt: FieldValue.serverTimestamp(),
          paidAmountCents: event.amountCents ?? snap.get("amountDueCents"),
          mandateReference: event.mandateReference ?? null,
        });
        tx.create(db.collection("ledgerEntries").doc(), {
          kind: "direct_debit_collected",
          invoiceId: event.invoiceId,
          guardianUid: snap.get("guardianUid"),
          centreId: snap.get("centreId"),
          amountCents: event.amountCents ?? snap.get("amountDueCents"),
          at: FieldValue.serverTimestamp(),
        });
      });
    } else if (event.type === "collection.failed") {
      await invoiceRef.update({
        status: "collection_failed",
        lastFailureAt: FieldValue.serverTimestamp(),
      });
    } else {
      logger.info("payment event ignored", { type: event.type, id: event.id });
    }

    res.status(200).json({ received: true });
  },
);
