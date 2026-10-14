import { fail, redirect, type Actions } from "@sveltejs/kit";
import { createSession, destroySession, verifyPassword } from "$lib/server/auth";
import { rateLimit } from "$lib/server/rate-limit";

const SESSION_COOKIE = "sid";
const TENANT_HINT_COOKIE = "last_tenant";
const EIGHT_HOURS = 60 * 60 * 8;
const THIRTY_DAYS = 60 * 60 * 24 * 30;

const BASE_COOKIE = {
  path: "/",
  httpOnly: true,
  secure: true,
  sameSite: "lax" as const
};

export const actions: Actions = {
  login: async ({ request, cookies, getClientAddress }) => {
    const form = await request.formData();
    const email = String(form.get("email") ?? "").trim().toLowerCase();
    const password = String(form.get("password") ?? "");
    if (!email || !password) return fail(400, { email, message: "email and password are required" });

    const allowed = await rateLimit(`login:${getClientAddress()}`, { limit: 10, windowSeconds: 300 });
    if (!allowed) return fail(429, { email, message: "too many attempts, try again shortly" });

    const user = await verifyPassword(email, password);
    if (!user) return fail(401, { email, message: "those credentials did not work" });

    const session = await createSession(user.id, getClientAddress());
    cookies.set(SESSION_COOKIE, session.token, { ...BASE_COOKIE, maxAge: EIGHT_HOURS });
    cookies.set(TENANT_HINT_COOKIE, user.tenantSlug, { ...BASE_COOKIE, httpOnly: false, maxAge: THIRTY_DAYS });

    throw redirect(303, form.get("next") === "billing" ? "/billing" : "/dashboard");
  },

  logout: async ({ cookies, locals }) => {
    if (locals.session) await destroySession(locals.session.id);
    cookies.delete(SESSION_COOKIE, { path: "/" });
    throw redirect(303, "/sign-in");
  }
};
