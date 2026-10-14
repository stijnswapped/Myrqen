import { defineMiddleware } from "astro:middleware";
import { randomUUID } from "node:crypto";
import { logger } from "./lib/logger";
import { SESSION_COOKIE, STAFF_COOKIE, loadCustomer, loadStaffRole, verify } from "./lib/session";

/**
 * Everything under /account and /api/orders is customer-only; everything under
 * /api/integrations is staff-only. The authenticated subject is resolved once
 * here and read from `locals` by the endpoints, so no endpoint parses the cookie
 * itself.
 */
const CUSTOMER_ONLY = [/^\/account(\/|$)/, /^\/api\/orders(\/|$)/, /^\/api\/downloads(\/|$)/, /^\/api\/previews(\/|$)/];
const STAFF_ONLY = [/^\/api\/integrations(\/|$)/, /^\/admin(\/|$)/];

export const onRequest = defineMiddleware(async (context, next) => {
  context.locals.requestId = randomUUID();
  context.locals.customer = null;
  context.locals.staffRole = null;

  const customerId = verify(context.cookies.get(SESSION_COOKIE)?.value);
  if (customerId) {
    context.locals.customer = await loadCustomer(customerId);
  }

  const pathname = new URL(context.request.url).pathname;

  if (CUSTOMER_ONLY.some((pattern) => pattern.test(pathname)) && !context.locals.customer) {
    logger.warn("anonymous request to a customer-only path", { pathname, requestId: context.locals.requestId });
    return new Response(JSON.stringify({ error: { code: "unauthenticated" } }), {
      status: 401,
      headers: { "content-type": "application/json" }
    });
  }

  if (STAFF_ONLY.some((pattern) => pattern.test(pathname))) {
    context.locals.staffRole = await resolveStaffRole(context.cookies.get(STAFF_COOKIE)?.value);
    if (!context.locals.staffRole) {
      return new Response(JSON.stringify({ error: { code: "forbidden" } }), {
        status: 403,
        headers: { "content-type": "application/json" }
      });
    }
  }

  return next();
});

async function resolveStaffRole(token: string | undefined): Promise<App.Locals["staffRole"]> {
  const staffId = verify(token);
  if (!staffId) return null;
  return loadStaffRole(staffId);
}
