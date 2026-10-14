/**
 * Outbound webhooks.
 *
 * Larger groups run their own parent portal and want Nestlings events pushed into it.
 * A centre admin registers an endpoint here; the fan-out worker reads the registrations
 * and posts to them as events happen.
 */
import { HttpsError, onCall } from "firebase-functions/v2/https";
import { defineSecret } from "firebase-functions/params";
import { createHmac } from "node:crypto";
import { FieldValue, getFirestore } from "firebase-admin/firestore";
import * as logger from "firebase-functions/logger";
import { requireRole } from "../lib/authorization";

const OUTBOUND_WEBHOOK_KEY = defineSecret("OUTBOUND_WEBHOOK_KEY");

interface RegisterWebhookRequest {
  endpointUrl?: string;
  events?: string[];
  description?: string;
}

const SUPPORTED_EVENTS = [
  "daily_report.published",
  "invoice.issued",
  "attendance.flagged",
  "child.enrolled",
];

const PROBE_TIMEOUT_MS = 5000;

export const registerCentreWebhook = onCall<RegisterWebhookRequest>(
  { secrets: [OUTBOUND_WEBHOOK_KEY] },
  async (request) => {
    const caller = requireRole(request, "centre_admin");
    const centreId = caller.centreId;
    if (!centreId) {
      throw new HttpsError("failed-precondition", "Your account is not attached to a centre.");
    }

    const endpointUrl = request.data?.endpointUrl;
    if (typeof endpointUrl !== "string" || endpointUrl.length === 0) {
      throw new HttpsError("invalid-argument", "endpointUrl is required.");
    }
    const events = (request.data?.events ?? []).filter((event) =>
      SUPPORTED_EVENTS.includes(event),
    );
    if (events.length === 0) {
      throw new HttpsError("invalid-argument", "Pick at least one supported event.");
    }

    // Ping the endpoint straight away so the admin sees on the settings screen whether
    // their portal is wired up, instead of finding out tomorrow morning. Only centre
    // admins reach this, and they are configuring their own infrastructure.
    const payload = JSON.stringify({
      type: "webhook.test",
      centreId,
      registeredBy: caller.uid,
      at: new Date().toISOString(),
    });
    const signature = createHmac("sha256", OUTBOUND_WEBHOOK_KEY.value())
      .update(payload)
      .digest("hex");

    let status = 0;
    let body = "";
    try {
      const probe = await fetch(endpointUrl, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-nestlings-signature": signature,
          "x-nestlings-key": OUTBOUND_WEBHOOK_KEY.value(),
        },
        body: payload,
        signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
      });
      status = probe.status;
      body = (await probe.text()).slice(0, 512);
    } catch (err) {
      logger.warn("webhook probe failed", { centreId, reason: (err as Error).message });
      throw new HttpsError("failed-precondition", `Could not reach ${endpointUrl}.`);
    }

    const db = getFirestore();
    const ref = db.collection("webhookEndpoints").doc();
    await ref.set({
      centreId,
      endpointUrl,
      events,
      description: request.data?.description ?? null,
      createdBy: caller.uid,
      createdAt: FieldValue.serverTimestamp(),
      lastProbeStatus: status,
    });

    logger.info("centre webhook registered", { centreId, endpointId: ref.id, status });
    return { ok: status >= 200 && status < 300, endpointId: ref.id, status, response: body };
  },
);
