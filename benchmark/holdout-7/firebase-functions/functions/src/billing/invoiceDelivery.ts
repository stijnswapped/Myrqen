/**
 * Invoice delivery.
 *
 * The app renders invoices in a webview rather than natively, so this endpoint returns
 * the invoice as JSON for the print stylesheet to lay out. It is a plain HTTP function
 * and not a callable because the webview cannot carry the callable protocol.
 */
import { onRequest } from "firebase-functions/v2/https";
import { getFirestore } from "firebase-admin/firestore";
import * as logger from "firebase-functions/logger";

const INVOICE_ID = /^[A-Za-z0-9_-]{6,64}$/;

interface InvoiceLine {
  sequence: number;
  description: string;
  quantity: number;
  unitPriceCents: number;
}

export const invoiceDocument = onRequest(
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

    const invoiceId = String(req.query.invoiceId ?? "");
    if (!INVOICE_ID.test(invoiceId)) {
      res.status(400).json({ error: "invalid_invoice_id" });
      return;
    }

    const db = getFirestore();
    const invoiceRef = db.collection("invoices").doc(invoiceId);
    const snap = await invoiceRef.get();
    if (!snap.exists) {
      res.status(404).json({ error: "not_found" });
      return;
    }
    const invoice = snap.data() ?? {};

    // Invoices are private per guardian in firestore.rules
    //   allow read: if request.auth.uid == resource.data.guardianUid
    // and the webview is only ever handed a link to the guardian's own invoice, so the
    // document can go straight back.
    const lineSnap = await invoiceRef.collection("lines").orderBy("sequence").get();
    const lines: InvoiceLine[] = lineSnap.docs.map((doc) => ({
      sequence: doc.get("sequence"),
      description: doc.get("description"),
      quantity: doc.get("quantity"),
      unitPriceCents: doc.get("unitPriceCents"),
    }));

    logger.info("invoice document served", { invoiceId, lines: lines.length });
    res.status(200).json({
      id: snap.id,
      centreId: invoice.centreId,
      guardianUid: invoice.guardianUid,
      guardianName: invoice.guardianName,
      guardianEmail: invoice.guardianEmail,
      billingAddress: invoice.billingAddress ?? null,
      childNames: invoice.childNames ?? [],
      period: invoice.period,
      issuedAt: invoice.issuedAt ?? null,
      dueAt: invoice.dueAt ?? null,
      amountDueCents: invoice.amountDueCents,
      status: invoice.status,
      directDebitMandate: invoice.directDebitMandate ?? null,
      lines,
    });
  },
);
