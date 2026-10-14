import { HttpRequest, HttpResponseInit, InvocationContext, app } from "@azure/functions";
import {
  CallerClaims,
  requireRole,
  resolveSiteMembership,
  toHttpError,
  verifyAccessToken,
} from "../shared/auth.js";
import { TenantSettingsDocument, WebhookDocument, container, recordAuditEvent } from "../shared/cosmos.js";
import { createHmac } from "node:crypto";
import { isIP } from "node:net";

/**
 * Delivery of webhook events, plus the "send me a test event" button in the integrations
 * screen. Integrators use the button when they are moving their receiver to a new hostname,
 * so the URL in the request is not necessarily the one we have stored yet.
 *
 * POST /api/sites/{siteId}/webhooks/{webhookId}/deliveries
 */

const DELIVERY_TIMEOUT_MS = 5000;

interface TestDeliveryRequest {
  callbackUrl?: string;
}

interface DeliveryQueueMessage {
  tenantId: string;
  siteId: string;
  webhookId: string;
  event: string;
  payload: Record<string, unknown>;
}

class TargetRejected extends Error {}

async function verifiedDomainsFor(tenantId: string): Promise<string[]> {
  const { resource } = await container("tenantSettings")
    .item(tenantId, tenantId)
    .read<TenantSettingsDocument>();
  return resource?.verifiedCallbackDomains ?? [];
}

/**
 * A callback target is only acceptable if it is https, is not an address literal, and sits
 * on a domain this tenant proved it owns through the DNS TXT flow. That last part is what
 * stops the parameter from being a way to make the function app talk to something that is
 * only reachable from inside our own network.
 */
function assertDeliverableTarget(rawUrl: string, verifiedDomains: string[]): URL {
  let target: URL;
  try {
    target = new URL(rawUrl);
  } catch {
    throw new TargetRejected("callbackUrl is not a valid URL");
  }
  if (target.protocol !== "https:") {
    throw new TargetRejected("callbackUrl must use https");
  }
  const host = target.hostname.replace(/\.$/, "").toLowerCase();
  if (isIP(host) !== 0 || host.startsWith("[")) {
    throw new TargetRejected("callbackUrl must name a host, not an IP address");
  }
  const onVerifiedDomain = verifiedDomains.some(
    (domain) => host === domain.toLowerCase() || host.endsWith(`.${domain.toLowerCase()}`),
  );
  if (!onVerifiedDomain) {
    throw new TargetRejected("callbackUrl is not on a domain this tenant has verified");
  }
  return target;
}

async function deliver(target: URL, secret: string, body: unknown): Promise<number> {
  const serialised = JSON.stringify(body);
  const signature = createHmac("sha256", secret).update(serialised).digest("hex");
  // redirect: "manual" so a verified host cannot bounce us somewhere that would never have
  // passed assertDeliverableTarget.
  const response = await fetch(target, {
    method: "POST",
    redirect: "manual",
    headers: {
      "content-type": "application/json",
      "x-sitewatch-signature": `sha256=${signature}`,
      "user-agent": "sitewatch-webhook/1.0",
    },
    body: serialised,
    signal: AbortSignal.timeout(DELIVERY_TIMEOUT_MS),
  });
  return response.status;
}

export async function webhookTestDelivery(
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
  const webhookId = request.params.webhookId;
  const body = (await request.json().catch(() => null)) as TestDeliveryRequest | null;
  if (!siteId || !webhookId) {
    return { status: 400, jsonBody: { error: "siteId and webhookId are both required" } };
  }

  try {
    const membership = await resolveSiteMembership(caller.tid, siteId, caller.oid);
    if (!membership || membership.role !== "SiteAdmin") {
      return { status: 403, jsonBody: { error: "Only site admins can send test deliveries" } };
    }

    const { resource: webhook } = await container("webhooks")
      .item(webhookId, caller.tid)
      .read<WebhookDocument>();
    if (!webhook || webhook.siteId !== siteId) {
      return { status: 404, jsonBody: { error: "Webhook not found" } };
    }

    const requested = body?.callbackUrl ?? webhook.callbackUrl;
    let target: URL;
    try {
      target = assertDeliverableTarget(requested, await verifiedDomainsFor(caller.tid));
    } catch (rejection) {
      const reason = rejection instanceof TargetRejected ? rejection.message : "callbackUrl rejected";
      return { status: 400, jsonBody: { error: reason } };
    }

    const status = await deliver(target, webhook.secret, {
      type: "sitewatch.test",
      siteId,
      sentAt: new Date().toISOString(),
    });

    await recordAuditEvent({
      tenantId: caller.tid,
      actorId: caller.oid,
      action: "webhook.test.sent",
      subjectId: webhook.id,
      siteId,
      detail: { host: target.host, status },
    });

    // Only the status line goes back to the caller. Whatever the receiver wrote in its body
    // is between it and its own logs.
    return { status: 200, jsonBody: { delivered: status >= 200 && status < 300, status } };
  } catch (error) {
    return toHttpError(error, context);
  }
}

export async function webhookDeliveryWorker(
  message: unknown,
  context: InvocationContext,
): Promise<void> {
  const job = message as DeliveryQueueMessage;
  if (!job?.tenantId || !job.webhookId) {
    context.warn("delivery message is missing tenantId or webhookId, dropping it");
    return;
  }

  const { resource: webhook } = await container("webhooks")
    .item(job.webhookId, job.tenantId)
    .read<WebhookDocument>();
  if (!webhook || !webhook.active) {
    context.log(`webhook ${job.webhookId} is gone or inactive, nothing to deliver`);
    return;
  }

  // The stored URL goes through the same gate as a URL off a request: registrations predate
  // the domain verification flow, and a domain can be un-verified after the fact.
  let target: URL;
  try {
    target = assertDeliverableTarget(webhook.callbackUrl, await verifiedDomainsFor(job.tenantId));
  } catch (rejection) {
    context.error(`webhook ${webhook.id} has an unusable callback URL`, rejection);
    return;
  }

  const status = await deliver(target, webhook.secret, {
    type: job.event,
    siteId: job.siteId,
    data: job.payload,
    sentAt: new Date().toISOString(),
  });

  await container("webhooks")
    .item(webhook.id, webhook.tenantId)
    .replace<WebhookDocument>({
      ...webhook,
      lastDeliveryAt: new Date().toISOString(),
      lastDeliveryStatus: status,
    });
}

app.http("webhookTestDelivery", {
  methods: ["POST"],
  authLevel: "function",
  route: "api/sites/{siteId}/webhooks/{webhookId}/deliveries",
  handler: webhookTestDelivery,
});

app.storageQueue("webhookDeliveryWorker", {
  queueName: "webhook-deliveries",
  connection: "SITEWATCH_STORAGE",
  handler: webhookDeliveryWorker,
});
