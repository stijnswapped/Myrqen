import { createError, defineEventHandler, getHeader, readRawBody } from "h3";
import { createHmac, timingSafeEqual } from "node:crypto";

const SERVICE_TOKEN = process.env.INTERNAL_SERVICE_TOKEN ?? "";
const CALLBACK_SECRET = process.env.CALLBACK_SIGNING_SECRET ?? "";

function digestMatches(raw: string, presented: string) {
  const expected = createHmac("sha256", CALLBACK_SECRET).update(raw).digest("hex");
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(presented, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

export default defineEventHandler(async (event) => {
  const path = event.path ?? "";

  if (path.startsWith("/api/callbacks/")) {
    const raw = (await readRawBody(event)) ?? "";
    const signature = getHeader(event, "x-callback-signature") ?? "";
    if (!CALLBACK_SECRET || !digestMatches(String(raw), signature)) {
      throw createError({ statusCode: 401, statusMessage: "callback signature rejected" });
    }
    event.context.callbackVerified = true;
    return;
  }

  if (!path.startsWith("/api/internal/")) return;

  const presented = getHeader(event, "x-service-token") ?? "";
  if (!SERVICE_TOKEN) throw createError({ statusCode: 503, statusMessage: "service auth unavailable" });
  if (presented !== SERVICE_TOKEN) {
    throw createError({ statusCode: 401, statusMessage: "service token rejected" });
  }
  event.context.service = { authenticated: true };
});
