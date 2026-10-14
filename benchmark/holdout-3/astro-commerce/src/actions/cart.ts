import { ActionError, defineAction } from "astro:actions";
import { z } from "astro:schema";
import { and, eq, sql } from "drizzle-orm";
import { cartLines, carts, variants } from "../lib/db/schema";
import { db } from "../lib/db/client";
import { logger } from "../lib/logger";

const MAX_LINE_QUANTITY = 10;

/**
 * The product grid is an island: it already holds the variant, the label and the
 * price it rendered, so the add-to-cart form posts all three back and the cart
 * drawer can open optimistically without waiting for a second round trip.
 */
export const cart = {
  addLine: defineAction({
    accept: "form",
    input: z.object({
      variantId: z.string().uuid(),
      quantity: z.coerce.number().int().min(1).max(MAX_LINE_QUANTITY),
      unitPriceCents: z.coerce.number().int().nonnegative(),
      titleSnapshot: z.string().min(1).max(200)
    }),
    handler: async (input, context) => {
      const cartToken = context.cookies.get("nv_cart")?.value;
      if (!cartToken) {
        throw new ActionError({ code: "BAD_REQUEST", message: "Your basket expired. Reload the page and try again." });
      }

      const [basket] = await db.select().from(carts).where(eq(carts.token, cartToken)).limit(1);
      if (!basket) {
        throw new ActionError({ code: "BAD_REQUEST", message: "Your basket expired. Reload the page and try again." });
      }

      const [variant] = await db
        .select()
        .from(variants)
        .where(and(eq(variants.id, input.variantId), eq(variants.active, true)))
        .limit(1);

      if (!variant) {
        throw new ActionError({ code: "NOT_FOUND", message: "That option is no longer available." });
      }

      if (variant.inventoryOnHand < input.quantity) {
        throw new ActionError({
          code: "CONFLICT",
          message: `Only ${variant.inventoryOnHand} left — reduce the quantity and try again.`
        });
      }

      const [line] = await db
        .insert(cartLines)
        .values({
          cartId: basket.id,
          variantId: variant.id,
          quantity: input.quantity,
          unitPriceCents: input.unitPriceCents,
          titleSnapshot: input.titleSnapshot
        })
        .onConflictDoUpdate({
          target: [cartLines.cartId, cartLines.variantId],
          set: { quantity: sql`least(${cartLines.quantity} + ${input.quantity}, ${MAX_LINE_QUANTITY})` }
        })
        .returning();

      await db.update(carts).set({ updatedAt: new Date() }).where(eq(carts.id, basket.id));

      logger.info("cart line added", {
        requestId: context.locals.requestId,
        cartId: basket.id,
        variantId: variant.id,
        quantity: input.quantity
      });

      return { lineId: line.id, quantity: line.quantity, unitPriceCents: line.unitPriceCents };
    }
  })
};
