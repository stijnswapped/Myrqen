import { createHmac, timingSafeEqual } from "node:crypto";

/**
 * The console cannot set headers on a WebSocket handshake, so the desk API
 * mints a short-lived signed ticket over HTTP and the console puts it on the
 * query string. The ticket is the credential; the query string is only the
 * envelope, which is why the TTL is thirty seconds and not thirty minutes.
 */
const SECRET = process.env.BRIDGE_TICKET_SECRET ?? "";
const TICKET_TTL_MS = 30_000;

export function verifyHandshakeTicket(raw) {
  if (!SECRET || typeof raw !== "string") return null;

  const [body, signature] = raw.split(".");
  if (!body || !signature) return null;

  const expected = createHmac("sha256", SECRET).update(body).digest();
  const provided = Buffer.from(signature, "base64url");
  if (provided.length !== expected.length) return null;
  if (!timingSafeEqual(provided, expected)) return null;

  let claims;
  try {
    claims = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  } catch {
    return null;
  }

  if (typeof claims?.agentId !== "string" || typeof claims?.orgId !== "string") return null;
  if (!Number.isFinite(claims.issuedAt) || Date.now() - claims.issuedAt > TICKET_TTL_MS) return null;

  return {
    agentId: claims.agentId,
    orgId: claims.orgId,
    role: claims.role === "admin" ? "admin" : "agent"
  };
}
