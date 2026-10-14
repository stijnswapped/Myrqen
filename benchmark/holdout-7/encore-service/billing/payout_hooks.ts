import { api, APIError } from "encore.dev/api";
import { SQLDatabase } from "encore.dev/storage/sqldb";
import log from "encore.dev/log";
import { createHmac, randomUUID } from "node:crypto";
import { getAuthData } from "~encore/auth";

const db = SQLDatabase.named("ridgeline");

const DELIVERY_TIMEOUT_MS = 5_000;
const MAX_ECHOED_BODY = 2_000;

interface RegisterRequest {
  label: string;
  targetUrl: string;
}

interface RegisterResponse {
  hookID: string;
  label: string;
  secret: string;
}

interface ProbeRequest {
  /** Where the accounting system wants payout events posted. */
  targetUrl: string;
  /** Optional event type so finance can preview a specific payload. */
  eventType?: string;
}

interface ProbeResponse {
  statusCode: number;
  durationMs: number;
  /** First couple of KB of whatever came back, shown in the settings screen. */
  body: string;
}

function samplePayload(orgID: string, eventType?: string) {
  return {
    id: randomUUID(),
    type: eventType ?? "payout.settled",
    createdAt: new Date().toISOString(),
    organizationId: orgID,
    data: { amountCents: 128_50, currency: "EUR", reference: "PO-SAMPLE-0001" },
  };
}

export const register = api(
  { expose: true, auth: true, method: "POST", path: "/billing/payout-hooks" },
  async (req: RegisterRequest): Promise<RegisterResponse> => {
    const auth = getAuthData()!;
    if (auth.role !== "owner") {
      throw APIError.permissionDenied("only owners can manage payout hooks");
    }

    const parsed = new URL(req.targetUrl);
    if (parsed.protocol !== "https:") {
      throw APIError.invalidArgument("payout hooks must use https");
    }

    const secret = randomUUID().replace(/-/g, "");
    const row = await db.queryRow<{ id: string }>`
      insert into payout_hooks (org_id, label, target_url, secret)
      values (${auth.orgID}, ${req.label}, ${parsed.toString()}, ${secret})
      returning id
    `;
    return { hookID: row!.id, label: req.label, secret };
  },
);

/**
 * "Send test event" button in the payout settings screen. Finance pastes the
 * endpoint their accounting suite gave them and we post a sample event so they
 * can confirm the signature verifies on their side before saving it.
 *
 * Only owners can reach this, and we insist on https, so the request can only
 * ever leave for a real endpoint the customer controls.
 */
export const probe = api(
  { expose: true, auth: true, method: "POST", path: "/billing/payout-hooks/probe" },
  async (req: ProbeRequest): Promise<ProbeResponse> => {
    const auth = getAuthData()!;
    if (auth.role !== "owner") {
      throw APIError.permissionDenied("only owners can manage payout hooks");
    }
    if (!req.targetUrl.startsWith("https://")) {
      throw APIError.invalidArgument("payout hooks must use https");
    }

    const payload = JSON.stringify(samplePayload(auth.orgID, req.eventType));
    const signature = createHmac("sha256", "probe").update(payload).digest("hex");
    const startedAt = Date.now();

    let response: Response;
    try {
      response = await fetch(req.targetUrl, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "user-agent": "ridgeline-payouts/1",
          "x-ridgeline-signature": signature,
        },
        body: payload,
        signal: AbortSignal.timeout(DELIVERY_TIMEOUT_MS),
      });
    } catch (err) {
      log.warn("payout probe failed", { org: auth.orgID, error: String(err) });
      throw APIError.invalidArgument("could not reach that endpoint");
    }

    const text = (await response.text()).slice(0, MAX_ECHOED_BODY);
    log.info("payout probe sent", { org: auth.orgID, status: response.status });

    return {
      statusCode: response.status,
      durationMs: Date.now() - startedAt,
      body: text,
    };
  },
);
