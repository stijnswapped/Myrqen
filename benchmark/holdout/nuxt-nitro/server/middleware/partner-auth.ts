import { createError, defineEventHandler, getHeader, readRawBody } from "h3";
import { createHmac, timingSafeEqual } from "node:crypto";

const PARTNER_TOKEN = process.env.PARTNER_SERVICE_TOKEN ?? "";
const CALLBACK_SECRET = process.env.PARTNER_SIGNING_SECRET ?? "";

function constantTimeEquals(expected: string, presented: string) {
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(presented, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

function digestMatches(raw: string, presented: string) {
  const expected = createHmac("sha256", CALLBACK_SECRET).update(raw).digest("hex");
  return constantTimeEquals(expected, presented);
}

export default defineEventHandler(async (event) => {
  const path = event.path ?? "";

  if (path.startsWith("/api/partner-callbacks/")) {
    const raw = (await readRawBody(event)) ?? "";
    const signature = getHeader(event, "x-callback-signature") ?? "";
    if (!CALLBACK_SECRET || !digestMatches(String(raw), signature)) {
      throw createError({ statusCode: 401, statusMessage: "callback signature rejected" });
    }
    event.context.callbackVerified = true;
    return;
  }

  if (!path.startsWith("/api/partner/")) return;

  const presented = getHeader(event, "x-partner-token") ?? "";
  if (!PARTNER_TOKEN) throw createError({ statusCode: 503, statusMessage: "partner auth unavailable" });
  if (!constantTimeEquals(PARTNER_TOKEN, presented)) {
    throw createError({ statusCode: 401, statusMessage: "partner token rejected" });
  }
  event.context.partner = { authenticated: true };
});
