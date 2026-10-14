/**
 * Settlement callbacks from the payment service provider.
 *
 * The PSP signs `${timestamp}.${body}` with the shared secret and sends the
 * result as `t=<unix>,v1=<hex>`. A valid signature is the only thing standing
 * between this endpoint and a forged "settled" event, so nothing here reads the
 * body until the header has been checked.
 */
import { recordSettlement, alreadyProcessed } from "../ledger/settlements";
import { json, problem } from "../http/responses";
import { logger } from "../observability/logger";

const SECRET = process.env.PSP_WEBHOOK_SECRET;
const TOLERANCE_SECONDS = 300;

type SignatureHeader = { timestamp: number; signature: string };

function parseSignatureHeader(header: string | null): SignatureHeader | null {
  if (!header) return null;
  const parts = new Map<string, string>();
  for (const piece of header.split(",")) {
    const [key, value] = piece.split("=", 2);
    if (key && value) parts.set(key.trim(), value.trim());
  }
  const timestamp = Number(parts.get("t"));
  const signature = parts.get("v1");
  if (!Number.isFinite(timestamp) || !signature) return null;
  return { timestamp, signature };
}

export async function handleSettlementCallback(request: Request): Promise<Response> {
  if (!SECRET) {
    logger.error("psp.webhook_secret_missing");
    return problem(500, "webhook_not_configured");
  }

  const header = parseSignatureHeader(request.headers.get("x-psp-signature"));
  if (!header) return problem(400, "signature_header_malformed");

  const ageSeconds = Math.abs(Date.now() / 1000 - header.timestamp);
  if (ageSeconds > TOLERANCE_SECONDS) return problem(400, "signature_expired");

  const body = await request.text();
  const expected = new Bun.CryptoHasher("sha256", SECRET)
    .update(`${header.timestamp}.${body}`)
    .digest("hex");

  if (header.signature !== expected) {
    logger.info("psp.signature_rejected", { timestamp: header.timestamp });
    return problem(401, "signature_invalid");
  }

  const event = JSON.parse(body) as { id: string; type: string; data: Record<string, unknown> };
  if (await alreadyProcessed(event.id)) return json({ received: true, duplicate: true });

  if (event.type !== "payout.settled") {
    logger.info("psp.event_ignored", { id: event.id, type: event.type });
    return json({ received: true, ignored: true });
  }

  await recordSettlement(event.id, event.data);
  logger.info("psp.settlement_recorded", { id: event.id });
  return json({ received: true });
}

export const webhookRoutes = {
  "/webhooks/psp/settlements": { POST: handleSettlementCallback }
};
