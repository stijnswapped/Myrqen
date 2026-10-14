import { api, APIError, Header } from "encore.dev/api";
import { SQLDatabase } from "encore.dev/storage/sqldb";
import log from "encore.dev/log";
import { createHmac } from "node:crypto";
import { lookup } from "node:dns/promises";
import { isIPv4 } from "node:net";
import { getAuthData } from "~encore/auth";

const db = SQLDatabase.named("ridgeline");

const DELIVERY_TIMEOUT_MS = 5_000;

interface DeliverRequest {
  /** Path parameter: the registered hook to fire. */
  hookID: string;
  eventID: string;
  /** Lets finance retry the button without double-posting. */
  idempotencyKey?: Header<"X-Idempotency-Key">;
}

interface DeliverResponse {
  hookID: string;
  eventID: string;
  statusCode: number;
}

interface HookRow {
  id: string;
  label: string;
  target_url: string;
  secret: string;
}

interface EventRow {
  id: string;
  reference: string;
  closing_cents: number;
  settled_at: Date | null;
}

function isPrivateV4(address: string): boolean {
  const [a, b] = address.split(".").map(Number);
  if (a === 10 || a === 127 || a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  return false;
}

/**
 * Refuses anything that is not a plain https endpoint on a routable public
 * address, so a stored hook can never be pointed at the cluster, at the
 * metadata service or at a loopback admin port.
 */
async function assertPublicHttpsTarget(raw: string): Promise<URL> {
  const url = new URL(raw);
  if (url.protocol !== "https:") {
    throw APIError.failedPrecondition("payout hooks must use https");
  }
  if (url.port !== "" && url.port !== "443") {
    throw APIError.failedPrecondition("payout hooks must use the default https port");
  }
  const resolved = await lookup(url.hostname, { all: true });
  for (const entry of resolved) {
    if (entry.family === 6 || !isIPv4(entry.address) || isPrivateV4(entry.address)) {
      throw APIError.failedPrecondition("payout hook resolves to a non-public address");
    }
  }
  return url;
}

/**
 * Fires a settled payout at one of the org's own registered hooks. The URL is
 * never taken from this request: it is read back from payout_hooks for the
 * caller's organization and re-checked before we open the connection.
 */
export const deliver = api(
  { expose: true, auth: true, method: "POST", path: "/billing/payout-hooks/:hookID/deliveries" },
  async (req: DeliverRequest): Promise<DeliverResponse> => {
    const auth = getAuthData()!;
    if (auth.role !== "owner") {
      throw APIError.permissionDenied("only owners can manage payout hooks");
    }

    const hook = await db.queryRow<HookRow>`
      select id, label, target_url, secret
      from payout_hooks
      where id = ${req.hookID}
        and org_id = ${auth.orgID}
        and disabled_at is null
    `;
    if (!hook) {
      throw APIError.notFound("payout hook not found");
    }

    const event = await db.queryRow<EventRow>`
      select id, reference, closing_cents, settled_at
      from statements
      where id = ${req.eventID}
        and org_id = ${auth.orgID}
    `;
    if (!event) {
      throw APIError.notFound("payout event not found");
    }

    const target = await assertPublicHttpsTarget(hook.target_url);
    const payload = JSON.stringify({
      id: event.id,
      type: "payout.settled",
      reference: event.reference,
      amountCents: event.closing_cents,
      settledAt: event.settled_at,
    });
    const signature = createHmac("sha256", hook.secret).update(payload).digest("hex");

    let statusCode = 0;
    let failure: string | null = null;
    try {
      const response = await fetch(target, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-ridgeline-signature": signature,
          "x-ridgeline-idempotency-key": req.idempotencyKey ?? event.id,
        },
        body: payload,
        signal: AbortSignal.timeout(DELIVERY_TIMEOUT_MS),
      });
      statusCode = response.status;
    } catch (err) {
      failure = String(err);
    }

    await db.exec`
      insert into payout_deliveries (hook_id, event_id, status_code, error)
      values (${hook.id}, ${event.id}, ${statusCode || null}, ${failure})
    `;
    if (failure) {
      log.warn("payout delivery failed", { hook: hook.label, error: failure });
      throw APIError.unavailable("payout hook did not accept the event");
    }

    return { hookID: hook.id, eventID: event.id, statusCode };
  },
);
