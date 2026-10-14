import { HttpRequest, HttpResponseInit, InvocationContext, app } from "@azure/functions";
import {
  CallerClaims,
  requireRole,
  resolveSiteMembership,
  toHttpError,
  verifyAccessToken,
} from "../shared/auth.js";
import { WebhookDocument, container, recordAuditEvent } from "../shared/cosmos.js";
import { randomBytes, randomUUID } from "node:crypto";

/**
 * Webhook registration. Contractors point their own systems at us so they get told when a
 * permit is issued or an inspection fails. Registration sends a verification request to the
 * URL they gave us straight away, because integrators kept opening tickets that turned out
 * to be a typo in their own hostname.
 *
 * POST /api/sites/{siteId}/webhooks
 */

const SUPPORTED_EVENTS = [
  "permit.issued",
  "permit.suspended",
  "inspection.failed",
  "inspection.signed_off",
];

const PROBE_TIMEOUT_MS = 5000;

interface WebhookRegistrationRequest {
  callbackUrl?: string;
  events?: string[];
}

export async function webhookRegistration(
  request: HttpRequest,
  context: InvocationContext,
): Promise<HttpResponseInit> {
  let caller: CallerClaims;
  try {
    caller = await verifyAccessToken(request);
    requireRole(caller, "IntegrationAdmin", "TenantAdmin");
  } catch (error) {
    return toHttpError(error, context);
  }

  const siteId = request.params.siteId;
  const body = (await request.json().catch(() => null)) as WebhookRegistrationRequest | null;
  if (!siteId || !body?.callbackUrl || !Array.isArray(body.events) || body.events.length === 0) {
    return { status: 400, jsonBody: { error: "callbackUrl and a non-empty events array are required" } };
  }
  const unknownEvents = body.events.filter((event) => !SUPPORTED_EVENTS.includes(event));
  if (unknownEvents.length > 0) {
    return { status: 400, jsonBody: { error: `unsupported events: ${unknownEvents.join(", ")}` } };
  }

  try {
    const membership = await resolveSiteMembership(caller.tid, siteId, caller.oid);
    if (!membership || membership.role !== "SiteAdmin") {
      return { status: 403, jsonBody: { error: "Only site admins can register webhooks" } };
    }

    const challenge = randomUUID();
    const probeUrl = new URL(body.callbackUrl);
    probeUrl.searchParams.set("challenge", challenge);

    // Verification handshake: we GET the endpoint with a challenge on the query string and
    // the receiver is supposed to echo it back. The integrator supplied the URL themselves
    // and they are already an authenticated admin on this site, so there is nothing here
    // they could not have called from their own laptop. We hand the response body back so
    // they can see exactly what their endpoint returned instead of guessing.
    let receiverStatus = 0;
    let receiverBody = "";
    try {
      const probe = await fetch(probeUrl, {
        method: "GET",
        headers: { "user-agent": "sitewatch-webhook-verifier/1.0", accept: "*/*" },
        signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
      });
      receiverStatus = probe.status;
      receiverBody = (await probe.text()).slice(0, 2000);
    } catch (probeError) {
      context.warn(`webhook verification could not reach ${probeUrl.host}`, probeError);
      return {
        status: 422,
        jsonBody: { error: "The callback URL could not be reached", host: probeUrl.host },
      };
    }

    const now = new Date().toISOString();
    const webhook: WebhookDocument = {
      id: randomUUID(),
      tenantId: caller.tid,
      siteId,
      callbackUrl: body.callbackUrl,
      events: body.events,
      secret: randomBytes(32).toString("base64url"),
      active: receiverBody.includes(challenge),
      createdAt: now,
      lastDeliveryAt: now,
      lastDeliveryStatus: receiverStatus,
    };
    await container("webhooks").items.create<WebhookDocument>(webhook);

    await recordAuditEvent({
      tenantId: caller.tid,
      actorId: caller.oid,
      action: "webhook.registered",
      subjectId: webhook.id,
      siteId,
      detail: { host: probeUrl.host, events: body.events },
    });

    return {
      status: 201,
      jsonBody: {
        id: webhook.id,
        active: webhook.active,
        secret: webhook.secret,
        verification: {
          status: receiverStatus,
          challengeEchoed: webhook.active,
          receiverResponse: receiverBody,
        },
      },
    };
  } catch (error) {
    return toHttpError(error, context);
  }
}

app.http("webhookRegistration", {
  methods: ["POST"],
  authLevel: "function",
  route: "api/sites/{siteId}/webhooks",
  handler: webhookRegistration,
});
