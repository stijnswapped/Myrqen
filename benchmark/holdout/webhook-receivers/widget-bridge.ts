import { Router } from "itty-router";

interface Env {
  DB: D1Database;
  SESSIONS: KVNamespace;
}

const router = Router();

const PARTNER_ORIGINS = new Set([
  "https://app.acme-suite.com",
  "https://status.acme-status.io",
  "http://localhost:5173"
]);

function corsHeaders(origin: string | null): Record<string, string> {
  if (!origin) return {};
  if (!PARTNER_ORIGINS.has(origin)) return {};
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-credentials": "true",
    "access-control-allow-headers": "content-type, x-requested-with",
    vary: "origin"
  };
}

router.options("/widget/*", (request: Request) => {
  return new Response(null, {
    status: 204,
    headers: { ...corsHeaders(request.headers.get("origin")), "access-control-allow-methods": "GET, POST" }
  });
});

router.get("/widget/summary", async (request: Request, env: Env) => {
  const sessionId = (request.headers.get("cookie") ?? "").match(/sid=([^;]+)/)?.[1];
  const session = sessionId ? await env.SESSIONS.get(sessionId, "json") : null;
  if (!session) return new Response("sign in required", { status: 401 });

  const row = await env.DB.prepare(
    "select plan, seats_used, seats_total, balance_cents from accounts where id = ?1"
  )
    .bind((session as { accountId: string }).accountId)
    .first();

  return Response.json(row, { headers: corsHeaders(request.headers.get("origin")) });
});

router.all("*", () => new Response("not found", { status: 404 }));

export default { fetch: router.handle };
