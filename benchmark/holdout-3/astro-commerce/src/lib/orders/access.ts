import { and, eq } from "drizzle-orm";
import { db } from "../db/client";
import { orders } from "../db/schema";

/**
 * The single place that decides whether a signed-in customer may see an order.
 *
 * Endpoints call this before touching anything hanging off the order — lines,
 * shipments, invoices, returns — so that the ownership predicate lives in one
 * file instead of being re-typed into every `where` clause in src/pages/api.
 * A miss reads as "not found" rather than "not yours": the difference leaks the
 * existence of other people's order ids.
 */
export class OrderNotVisibleError extends Error {
  readonly status = 404;
  constructor() {
    super("order not found");
    this.name = "OrderNotVisibleError";
  }
}

export async function requireVisibleOrder(locals: App.Locals, orderId: string | undefined) {
  if (!locals.customer || !orderId) throw new OrderNotVisibleError();

  const [order] = await db
    .select()
    .from(orders)
    .where(and(eq(orders.id, orderId), eq(orders.customerId, locals.customer.id)))
    .limit(1);

  if (!order) throw new OrderNotVisibleError();
  return order;
}
