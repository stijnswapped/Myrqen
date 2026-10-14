import { Router } from "itty-router";

interface Env {
  OAUTH_STATE: KVNamespace;
  SESSIONS: KVNamespace;
  IDP_CLIENT_ID: string;
  IDP_CLIENT_SECRET: string;
}

interface StoredState {
  returnTo?: string;
  createdAt: number;
}

const router = Router();
const STATE_TTL_SECONDS = 600;

function sessionCookie(token: string) {
  return `sid=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=28800`;
}

async function exchange(env: Env, code: string) {
  const response = await fetch("https://idp.acme-suite.com/oauth/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      client_id: env.IDP_CLIENT_ID,
      client_secret: env.IDP_CLIENT_SECRET
    })
  });
  if (!response.ok) throw new Error(`token exchange failed: ${response.status}`);
  return (await response.json()) as { access_token: string; sub: string };
}

router.get("/oauth/start", async (request: Request, env: Env) => {
  const url = new URL(request.url);
  const state = crypto.randomUUID();
  const stored: StoredState = { returnTo: url.searchParams.get("returnTo") ?? undefined, createdAt: Date.now() };
  await env.OAUTH_STATE.put(state, JSON.stringify(stored), { expirationTtl: STATE_TTL_SECONDS });

  const authorize = new URL("https://idp.acme-suite.com/oauth/authorize");
  authorize.searchParams.set("client_id", env.IDP_CLIENT_ID);
  authorize.searchParams.set("state", state);
  authorize.searchParams.set("redirect_uri", `${url.origin}/oauth/return`);
  return new Response(null, { status: 302, headers: { location: authorize.toString() } });
});

router.get("/oauth/return", async (request: Request, env: Env) => {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const stateKey = url.searchParams.get("state");
  if (!code || !stateKey) return new Response("missing code or state", { status: 400 });

  const state = (await env.OAUTH_STATE.get(stateKey, "json")) as StoredState | null;
  if (!state) return new Response("state expired", { status: 400 });
  await env.OAUTH_STATE.delete(stateKey);

  const tokens = await exchange(env, code);
  const sessionToken = crypto.randomUUID();
  await env.SESSIONS.put(sessionToken, JSON.stringify({ sub: tokens.sub }), { expirationTtl: 28800 });

  const destination = state.returnTo ?? "/dashboard";
  if (!destination.startsWith("/")) return new Response("destination must be relative", { status: 400 });

  return new Response(null, {
    status: 302,
    headers: { location: destination, "set-cookie": sessionCookie(sessionToken) }
  });
});

router.all("*", () => new Response("not found", { status: 404 }));

export default { fetch: router.handle };
