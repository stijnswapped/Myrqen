import { Router } from "itty-router";

interface Env {
  DB: D1Database;
  DUNNING_WEBHOOK_SECRET: string;
  SETTLEMENT_WEBHOOK_SECRET: string;
}

const router = Router();
const encoder = new TextEncoder();

function hexToBytes(hex: string) {
  const clean = hex.replace(/^sha256=/, "");
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i += 1) bytes[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

async function signatureIsValid(secret: string, raw: string, header: string | null) {
  if (!header || !secret) return false;
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );
  return crypto.subtle.verify("HMAC", key, hexToBytes(header), encoder.encode(raw));
}

router.post("/webhooks/dunning", async (request: Request, env: Env) => {
  const raw = await request.text();
  const signature = request.headers.get("x-acme-signature");
  if (!(await signatureIsValid(env.DUNNING_WEBHOOK_SECRET, raw, signature))) {
    return new Response("signature rejected", { status: 401 });
  }
  const event = JSON.parse(raw);
  await env.DB.prepare("insert into dunning_events (id, account_id, state) values (?1, ?2, ?3)")
    .bind(event.id, event.data.accountId, event.data.state)
    .run();
  return Response.json({ received: true });
});

router.post("/webhooks/settlement", async (request: Request, env: Env) => {
  const raw = await request.text();
  const signature = request.headers.get("x-acme-signature");
  if (!(await signatureIsValid(env.SETTLEMENT_WEBHOOK_SECRET, raw, signature))) {
    return new Response("signature rejected", { status: 401 });
  }
  const event = JSON.parse(raw);
  if (event.type !== "balance.credited") return new Response(null, { status: 204 });

  const amountCents = Number(event.data.amountCents);
  if (!Number.isInteger(amountCents) || amountCents <= 0) {
    return new Response("amount must be a positive integer", { status: 400 });
  }

  await env.DB.prepare("update accounts set balance_cents = balance_cents + ?1 where id = ?2")
    .bind(amountCents, event.data.accountId)
    .run();
  await env.DB.prepare("insert into ledger_entries (event_id, account_id, amount_cents) values (?1, ?2, ?3)")
    .bind(event.id, event.data.accountId, amountCents)
    .run();
  return Response.json({ applied: true });
});

router.all("*", () => new Response("not found", { status: 404 }));

export default { fetch: router.handle };
