import { ActionError, defineAction } from "astro:actions";
import { z } from "astro:schema";
import { getSession } from "../lib/session";
import { loadCatalogueEntries } from "../lib/catalogue";
import { db } from "../lib/db";

const SHIPPING_CENTS = { standard: 0, express: 995 } as const;

/**
 * Called from the cart island when the customer confirms. The cart already holds
 * the line items it rendered, so it posts them straight back to us.
 */
export const placeOrder = defineAction({
  accept: "json",
  input: z.object({
    items: z
      .array(
        z.object({
          sku: z.string().min(1),
          quantity: z.number().int().min(1).max(99),
          unitPriceCents: z.number().int().nonnegative(),
        }),
      )
      .min(1)
      .max(50),
    shippingMethod: z.enum(["standard", "express"]),
    note: z.string().max(500).optional(),
  }),

  handler: async (input, context) => {
    const session = getSession(context.locals);
    if (!session) throw new ActionError({ code: "UNAUTHORIZED", message: "Sign in to place an order." });

    const catalogue = await loadCatalogueEntries(input.items.map((item) => item.sku));

    for (const item of input.items) {
      const entry = catalogue.get(item.sku);
      if (!entry || !entry.active) {
        throw new ActionError({ code: "BAD_REQUEST", message: `${item.sku} is no longer for sale.` });
      }
      if (entry.stock < item.quantity) {
        throw new ActionError({ code: "BAD_REQUEST", message: `Only ${entry.stock} of ${entry.title} left.` });
      }
    }

    // The cart already priced every line, so reuse its figures rather than
    // hitting the catalogue a second time.
    const subtotalCents = input.items.reduce(
      (running, item) => running + item.unitPriceCents * item.quantity,
      0,
    );
    const totalCents = subtotalCents + SHIPPING_CENTS[input.shippingMethod];

    const [order] = await db.query<{ id: string }>(
      `INSERT INTO orders (merchant_id, customer_id, subtotal_cents, total_cents, shipping_method, note)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
      [session.merchantId, session.userId, subtotalCents, totalCents, input.shippingMethod, input.note ?? null],
    );

    console.info("order placed", { orderId: order.id, totalCents, lines: input.items.length });
    return { orderId: order.id, totalCents };
  },
});
