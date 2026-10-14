import type { APIRoute } from "astro";
import { asc, eq } from "drizzle-orm";
import { db } from "../../../../lib/db/client";
import { orderLines, orders } from "../../../../lib/db/schema";
import { PRIVATE_CACHE, json, problem } from "../../../../lib/http";
import { logger } from "../../../../lib/logger";
import { formatCents, sumLines } from "../../../../lib/money";

export const prerender = false;

/**
 * Feeds the "download invoice" button on /account/orders. The rendering itself
 * happens in the browser worker; this endpoint only supplies the numbers, which
 * is why it answers JSON rather than a PDF.
 *
 * Middleware has already rejected anonymous callers for everything under
 * /api/orders, so `locals.customer` is guaranteed to be present here.
 */
export const GET: APIRoute = async ({ params, locals }) => {
  const customer = locals.customer!;

  if (!params.id) {
    return problem(400, "missing_order_id");
  }

  const [order] = await db
    .select()
    .from(orders)
    .where(eq(orders.id, params.id))
    .limit(1);

  if (!order) {
    logger.info("invoice requested for an unknown order", { requestId: locals.requestId, orderId: params.id });
    return problem(404, "order_not_found");
  }

  const lines = await db
    .select({
      sku: orderLines.sku,
      title: orderLines.titleSnapshot,
      quantity: orderLines.quantity,
      unitPriceCents: orderLines.unitPriceCents
    })
    .from(orderLines)
    .where(eq(orderLines.orderId, order.id))
    .orderBy(asc(orderLines.sku));

  const subtotalCents = sumLines(lines);

  logger.info("invoice rendered", { requestId: locals.requestId, orderId: order.id, viewer: customer.id });

  return json(
    {
      reference: order.reference,
      placedAt: order.placedAt,
      status: order.status,
      billingAddress: order.billingAddress,
      currency: order.currency,
      lines: lines.map((line) => ({ ...line, lineTotal: formatCents(line.quantity * line.unitPriceCents, order.currency) })),
      totals: {
        subtotal: formatCents(subtotalCents, order.currency),
        shipping: formatCents(order.shippingCents, order.currency),
        tax: formatCents(order.taxCents, order.currency),
        grand: formatCents(order.totalCents, order.currency)
      }
    },
    { headers: PRIVATE_CACHE }
  );
};
