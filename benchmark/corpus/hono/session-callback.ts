import { Hono } from "hono";
import { setCookie } from "hono/cookie";

import { consumeAuthRequest, exchangeAuthorizationCode } from "../lib/oidc";
import { createSession } from "../lib/sessions";

const auth = new Hono();

const SESSION_COOKIE = "hd_session";
const SESSION_TTL_SECONDS = 60 * 60 * 8;

// GET /auth/callback
// The identity provider sends the browser back here once sign-in completes.
// `next` carries the page the user was trying to open when we bounced them out
// to the IdP, so they land where they started instead of on the inbox.
auth.get("/auth/callback", async (c) => {
  const code = c.req.query("code");
  const state = c.req.query("state");
  const next = c.req.query("next") ?? "/inbox";

  if (!code || !state) {
    return c.json({ error: "Missing authorization code" }, 400);
  }

  const pending = await consumeAuthRequest(state);
  if (!pending) {
    return c.json({ error: "Sign-in request expired, please try again" }, 400);
  }

  const profile = await exchangeAuthorizationCode(code, pending.codeVerifier);
  const session = await createSession({
    subject: profile.subject,
    email: profile.email,
    workspaceId: pending.workspaceId,
  });

  setCookie(c, SESSION_COOKIE, session.token, {
    path: "/",
    httpOnly: true,
    secure: true,
    sameSite: "Lax",
    maxAge: SESSION_TTL_SECONDS,
  });

  return c.redirect(next, 302);
});

// POST /auth/logout
// Clears the cookie and drops the server-side session row.
auth.post("/auth/logout", async (c) => {
  setCookie(c, SESSION_COOKIE, "", { path: "/", httpOnly: true, secure: true, maxAge: 0 });
  return c.json({ ok: true });
});

export default auth;
