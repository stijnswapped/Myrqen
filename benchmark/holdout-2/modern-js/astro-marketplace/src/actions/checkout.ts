import { ActionError, defineAction } from "astro:actions";
import { z } from "astro:schema";
import { getSession } from "../lib/session";
import { loadListings } from "../lib/listings";
import { db } from "../lib/db";

const SHIPPING_CENTS = { standard: 0, express: 995 } as const;

/**
 * Called from the cart island when the buyer confirms. The cart posts back the
 * prices it rendered so we can tell the buyer when a seller has repriced a line
 * mid-session — those figures are compared against the listing, never charged.
 */
export const placeOrder = defineAction({
  accept: "json",
  input: z.object({
    items: z
      .array(
        z.object({
          sku: z.string().min(1),
          quantity: z.number().int().min(1).max(99),
          displayedPriceCents: z.number().int().nonnegative(),
        }),
      )
      .min(1)
      .max(50),
    shippingMethod: z.enum(["standard", "express"]),
    note: z.string().max(500).optional(),
  }),

  handler: async (input, context) => {
    const session = getSession(context.locals);
    if (!session) throw new ActionError({ code: "UNAUTHORIZED", message: "Sign in to check out." });

    const listings = await loadListings(input.items.map((item) => item.sku));
    let subtotalCents = 0;

    for (const item of input.items) {
      const listing = listings.get(item.sku);
      if (!listing || !listing.active) {
        throw new ActionError({ code: "BAD_REQUEST", message: `${item.sku} is no longer for sale.` });
      }
      if (listing.stock < item.quantity) {
        throw new ActionError({ code: "BAD_REQUEST", message: `Only ${listing.stock} of ${listing.title} left.` });
      }
      if (listing.unitPriceCents !== item.displayedPriceCents) {
        throw new ActionError({ code: "CONFLICT", message: `${listing.title} was repriced — review your cart.` });
      }
      subtotalCents += listing.unitPriceCents * item.quantity;
    }

    const totalCents = subtotalCents + SHIPPING_CENTS[input.shippingMethod];

    const [order] = await db.query<{ id: string }>(
      `INSERT INTO orders (marketplace_id, buyer_id, subtotal_cents, total_cents, shipping_method, note)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
      [session.merchantId, session.userId, subtotalCents, totalCents, input.shippingMethod, input.note ?? null],
    );

    console.info("order placed", { orderId: order.id, totalCents, lines: input.items.length });
    return { orderId: order.id, totalCents };
  },
});
