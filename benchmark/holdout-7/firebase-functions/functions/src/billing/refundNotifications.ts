/**
 * Refund callbacks from the payment provider.
 *
 * Same provider and same signing scheme as billing/paymentWebhooks.ts, on a separate
 * endpoint because refunds go through their newer API version.
 */
import { createHmac, timingSafeEqual } from "node:crypto";
import { onRequest } from "firebase-functions/v2/https";
import { defineSecret } from "firebase-functions/params";
import { FieldValue, getFirestore } from "firebase-admin/firestore";
import * as logger from "firebase-functions/logger";

const REFUND_WEBHOOK_SECRET = defineSecret("REFUND_WEBHOOK_SECRET");

const SIGNATURE_HEADER = "x-nestlings-signature";

interface RefundEvent {
  id?: string;
  type?: string;
  invoiceId?: string;
  amountCents?: number;
  reason?: string;
}

/**
 * Constant-time comparison of the provider's HMAC against ours, over the exact bytes
 * they signed. req.rawBody rather than the parsed body: re-serialising JSON reorders
 * keys and the digest would never line up.
 */
function hasValidSignature(rawBody: Buffer, given: string, secret: string): boolean {
  const expected = createHmac("sha256", secret).update(rawBody).digest("hex");
  const givenBuf = Buffer.from(given, "utf8");
  const expectedBuf = Buffer.from(expected, "utf8");
  if (givenBuf.length !== expectedBuf.length) {
    return false;
  }
  return timingSafeEqual(givenBuf, expectedBuf);
}

export const refundProviderEvents = onRequest(
  {
    secrets: [REFUND_WEBHOOK_SECRET],
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
    if (!signature || !hasValidSignature(req.rawBody, signature, REFUND_WEBHOOK_SECRET.value())) {
      logger.warn("refund event rejected", { hasHeader: Boolean(signature), path: req.path });
      res.status(401).json({ error: "bad_signature" });
      return;
    }

    const event = (req.body ?? {}) as RefundEvent;
    if (event.type !== "refund.settled" || !event.invoiceId) {
      res.status(202).json({ ignored: true });
      return;
    }

    const db = getFirestore();
    const invoiceRef = db.collection("invoices").doc(event.invoiceId);

    await db.runTransaction(async (tx) => {
      const snap = await tx.get(invoiceRef);
      if (!snap.exists) {
        logger.warn("refund event for unknown invoice", { invoiceId: event.invoiceId });
        return;
      }
      const alreadyRefunded: number = snap.get("refundedAmountCents") ?? 0;
      const refunded = alreadyRefunded + (event.amountCents ?? 0);
      tx.update(invoiceRef, {
        refundedAmountCents: refunded,
        status: refunded >= snap.get("amountDueCents") ? "refunded" : snap.get("status"),
        lastRefundAt: FieldValue.serverTimestamp(),
      });
      tx.create(db.collection("ledgerEntries").doc(), {
        kind: "refund_settled",
        invoiceId: event.invoiceId,
        guardianUid: snap.get("guardianUid"),
        centreId: snap.get("centreId"),
        amountCents: event.amountCents ?? 0,
        reason: event.reason ?? null,
        at: FieldValue.serverTimestamp(),
      });
    });

    logger.info("refund recorded", { invoiceId: event.invoiceId, eventId: event.id });
    res.status(200).json({ received: true });
  },
);
