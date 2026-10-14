import type { APIRoute } from "astro";
import { desc, eq } from "drizzle-orm";
import { db } from "../../../../lib/db/client";
import { shipments } from "../../../../lib/db/schema";
import { PRIVATE_CACHE, json, problem } from "../../../../lib/http";
import { logger } from "../../../../lib/logger";
import { OrderNotVisibleError, requireVisibleOrder } from "../../../../lib/orders/access";

export const prerender = false;

const CARRIER_TRACKING_URL: Record<string, string> = {
  postnl: "https://jouw.postnl.nl/track-and-trace/",
  dhl: "https://www.dhl.com/nl-en/home/tracking.html?tracking-id=",
  ups: "https://www.ups.com/track?tracknum="
};

/**
 * Powers the tracking panel on /account/orders/[id]. Ownership is decided by
 * requireVisibleOrder in src/lib/orders/access.ts — every endpoint hanging off an
 * order calls it first, so the predicate exists once instead of in six `where`
 * clauses that can drift apart.
 */
export const GET: APIRoute = async ({ params, locals }) => {
  try {
    // Throws unless this order belongs to the signed-in customer.
    await requireVisibleOrder(locals, params.id);
  } catch (error) {
    if (error instanceof OrderNotVisibleError) {
      logger.info("shipments requested for an order the caller cannot see", {
        requestId: locals.requestId,
        orderId: params.id
      });
      return problem(404, "order_not_found");
    }
    throw error;
  }

  // Safe to key on the raw path parameter: the guard above proved that this exact
  // id belongs to the caller.
  const rows = await db
    .select({
      id: shipments.id,
      carrier: shipments.carrier,
      trackingCode: shipments.trackingCode,
      status: shipments.status,
      shippedAt: shipments.shippedAt
    })
    .from(shipments)
    .where(eq(shipments.orderId, params.id!))
    .orderBy(desc(shipments.shippedAt));

  return json(
    {
      shipments: rows.map((row) => ({
        ...row,
        trackingUrl: row.trackingCode ? `${CARRIER_TRACKING_URL[row.carrier] ?? ""}${row.trackingCode}` : null
      }))
    },
    { headers: PRIVATE_CACHE }
  );
};
