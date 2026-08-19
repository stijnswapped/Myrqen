import { Hono } from "hono";
import { setCookie } from "hono/cookie";

import { consumeMagicLink } from "../lib/magic-links";
import { createSession } from "../lib/sessions";

const magicLink = new Hono();

const SESSION_COOKIE = "hd_session";
const SESSION_TTL_SECONDS = 60 * 60 * 8;
const APP_ORIGIN = process.env.APP_ORIGIN ?? "https://app.helpdesk.example";
const DEFAULT_LANDING = "/inbox";

// Sign-in links carry the page the user was trying to open. Only paths inside
// this deployment are honoured; anything else falls back to the inbox.
function resolveLanding(raw: string | undefined): string {
  if (!raw) {
    return DEFAULT_LANDING;
  }

  let target: URL;
  try {
    target = new URL(raw, APP_ORIGIN);
  } catch {
    return DEFAULT_LANDING;
  }

  if (target.origin !== APP_ORIGIN) {
    return DEFAULT_LANDING;
  }

  return `${target.pathname}${target.search}`;
}

// GET /auth/link
// Consumes a one-time e-mail sign-in token and starts the session.
magicLink.get("/auth/link", async (c) => {
  const token = c.req.query("token");
  const next = c.req.query("next") ?? DEFAULT_LANDING;

  if (!token) {
    return c.json({ error: "Missing sign-in token" }, 400);
  }

  const invitation = await consumeMagicLink(token);
  if (!invitation) {
    return c.json({ error: "This sign-in link has expired, please request a new one" }, 400);
  }

  const session = await createSession({
    subject: invitation.subject,
    email: invitation.email,
    workspaceId: invitation.workspaceId,
  });

  setCookie(c, SESSION_COOKIE, session.token, {
    path: "/",
    httpOnly: true,
    secure: true,
    sameSite: "Lax",
    maxAge: SESSION_TTL_SECONDS,
  });

  return c.redirect(resolveLanding(next), 302);
});

export default magicLink;
