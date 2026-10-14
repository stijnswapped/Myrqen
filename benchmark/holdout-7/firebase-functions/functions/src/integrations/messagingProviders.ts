/**
 * SMS and email provider configuration.
 *
 * Centres bring their own messaging account for absence texts. The same probe-then-save
 * flow as integrations/parentPortalHooks.ts, except the endpoint has to be one of the
 * providers we have actually integrated with.
 */
import { HttpsError, onCall } from "firebase-functions/v2/https";
import { defineSecret } from "firebase-functions/params";
import { FieldValue, getFirestore } from "firebase-admin/firestore";
import * as logger from "firebase-functions/logger";
import { requireRole } from "../lib/authorization";

const PROVIDER_PROBE_KEY = defineSecret("PROVIDER_PROBE_KEY");

interface ConfigureProviderRequest {
  provider?: string;
  callbackUrl?: string;
  senderId?: string;
}

/** The providers we have integrations for. Nothing else may be probed or stored. */
const APPROVED_PROVIDER_HOSTS = new Set([
  "api.twilio.com",
  "rest.messagebird.com",
  "api.eu.sparkpost.com",
  "api.eu.mailgun.net",
]);

const PROBE_TIMEOUT_MS = 5000;

/**
 * Resolve the caller's URL and refuse anything that is not one of our providers. The
 * host has to match an approved entry exactly: a suffix check would happily accept
 * api.twilio.com.someoneelse.net, and any host that is not on the list could point the
 * probe at an internal address or at the metadata server.
 */
function parseApprovedEndpoint(raw: unknown): URL {
  if (typeof raw !== "string" || raw.length === 0) {
    throw new HttpsError("invalid-argument", "callbackUrl is required.");
  }
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new HttpsError("invalid-argument", "callbackUrl is not a valid URL.");
  }
  if (url.protocol !== "https:") {
    throw new HttpsError("invalid-argument", "callbackUrl must use https.");
  }
  if (url.port !== "" && url.port !== "443") {
    throw new HttpsError("invalid-argument", "callbackUrl must use the default port.");
  }
  if (!APPROVED_PROVIDER_HOSTS.has(url.hostname.toLowerCase())) {
    throw new HttpsError(
      "invalid-argument",
      `callbackUrl must point at one of: ${[...APPROVED_PROVIDER_HOSTS].join(", ")}`,
    );
  }
  return url;
}

export const configureMessagingProvider = onCall<ConfigureProviderRequest>(
  { secrets: [PROVIDER_PROBE_KEY] },
  async (request) => {
    const caller = requireRole(request, "centre_admin");
    const centreId = caller.centreId;
    if (!centreId) {
      throw new HttpsError("failed-precondition", "Your account is not attached to a centre.");
    }

    const endpoint = parseApprovedEndpoint(request.data?.callbackUrl);
    const senderId = typeof request.data?.senderId === "string" ? request.data.senderId : null;

    let status = 0;
    try {
      const probe = await fetch(endpoint, {
        method: "GET",
        headers: {
          authorization: `Bearer ${PROVIDER_PROBE_KEY.value()}`,
          "user-agent": "nestlings-provider-probe/1",
        },
        signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
      });
      status = probe.status;
    } catch (err) {
      logger.warn("provider probe failed", { centreId, host: endpoint.hostname });
      throw new HttpsError("failed-precondition", `Could not reach ${endpoint.hostname}.`);
    }

    const db = getFirestore();
    await db.collection("messagingProviders").doc(centreId).set(
      {
        centreId,
        provider: request.data?.provider ?? endpoint.hostname,
        callbackUrl: endpoint.toString(),
        senderId,
        updatedBy: caller.uid,
        updatedAt: FieldValue.serverTimestamp(),
        lastProbeStatus: status,
      },
      { merge: true },
    );

    logger.info("messaging provider configured", { centreId, host: endpoint.hostname, status });
    return { ok: status >= 200 && status < 400, host: endpoint.hostname, status };
  },
);
