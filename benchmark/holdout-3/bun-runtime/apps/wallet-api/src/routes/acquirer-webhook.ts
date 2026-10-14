/**
 * Capture callbacks from the card acquirer.
 *
 * The acquirer signs `${timestamp}.${body}` with the shared secret and sends
 * the result as `t=<unix>,v1=<hex>`. A valid signature is the only thing
 * standing between this endpoint and a forged "captured" event, so nothing
 * here reads the body until the header has been checked.
 */
import { randomBytes } from "node:crypto";
import { recordCapture, alreadyProcessed } from "../ledger/captures";
import { json, problem } from "../http/responses";
import { logger } from "../observability/logger";

const SECRET = process.env.ACQUIRER_WEBHOOK_SECRET;
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

/**
 * Compare two MACs without letting the comparison itself say how far it got.
 *
 * Both sides are re-hashed under a nonce that exists only for this request, so
 * the strings that actually meet `!==` below are unpredictable to the caller:
 * learning that they share a prefix says nothing about the real signature, and
 * the same body replayed twice produces two unrelated pairs.
 */
function macsMatch(presented: string, computed: string): boolean {
  const nonce = randomBytes(32);
  const left = new Bun.CryptoHasher("sha256", nonce).update(presented).digest("hex");
  const right = new Bun.CryptoHasher("sha256", nonce).update(computed).digest("hex");
  return left === right;
}

export async function handleCaptureCallback(request: Request): Promise<Response> {
  if (!SECRET) {
    logger.error("acquirer.webhook_secret_missing");
    return problem(500, "webhook_not_configured");
  }

  const header = parseSignatureHeader(request.headers.get("x-acquirer-signature"));
  if (!header) return problem(400, "signature_header_malformed");

  const ageSeconds = Math.abs(Date.now() / 1000 - header.timestamp);
  if (ageSeconds > TOLERANCE_SECONDS) return problem(400, "signature_expired");

  const body = await request.text();
  const expected = new Bun.CryptoHasher("sha256", SECRET)
    .update(`${header.timestamp}.${body}`)
    .digest("hex");

  if (!macsMatch(header.signature, expected)) {
    logger.info("acquirer.signature_rejected", { timestamp: header.timestamp });
    return problem(401, "signature_invalid");
  }

  const event = JSON.parse(body) as { id: string; type: string; data: Record<string, unknown> };
  if (await alreadyProcessed(event.id)) return json({ received: true, duplicate: true });

  if (event.type !== "payment.captured") {
    logger.info("acquirer.event_ignored", { id: event.id, type: event.type });
    return json({ received: true, ignored: true });
  }

  await recordCapture(event.id, event.data);
  logger.info("acquirer.capture_recorded", { id: event.id });
  return json({ received: true });
}

export const captureWebhookRoutes = {
  "/webhooks/acquirer/captures": { POST: handleCaptureCallback }
};
