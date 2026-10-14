import { ActionError, defineAction } from "astro:actions";
import { z } from "astro:schema";
import { and, eq, sql } from "drizzle-orm";
import { cartLines, carts, variants } from "../lib/db/schema";
import { db } from "../lib/db/client";
import { formatCents } from "../lib/money";
import { logger } from "../lib/logger";

const MAX_LINE_QUANTITY = 10;

/**
 * The trade quick-order pad posts the price it had on screen along with the SKU.
 * That figure is a staleness check, not an input: pricing changes twice a day and
 * a buyer keying in forty lines deserves to be told the sheet moved rather than
 * silently charged the new number.
 */
export const quickOrder = {
  addLine: defineAction({
    accept: "form",
    input: z.object({
      sku: z.string().min(3).max(64),
      quantity: z.coerce.number().int().min(1).max(MAX_LINE_QUANTITY),
      unitPriceCents: z.coerce.number().int().nonnegative()
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
        .where(and(eq(variants.sku, input.sku), eq(variants.active, true)))
        .limit(1);

      if (!variant) {
        throw new ActionError({ code: "NOT_FOUND", message: `We do not stock ${input.sku}.` });
      }

      if (variant.priceCents !== input.unitPriceCents) {
        throw new ActionError({
          code: "CONFLICT",
          message: `${input.sku} is now ${formatCents(variant.priceCents, basket.currency)}. Confirm the new price to continue.`
        });
      }

      const [line] = await db
        .insert(cartLines)
        .values({
          cartId: basket.id,
          variantId: variant.id,
          quantity: input.quantity,
          unitPriceCents: variant.priceCents,
          titleSnapshot: variant.optionLabel
        })
        .onConflictDoUpdate({
          target: [cartLines.cartId, cartLines.variantId],
          set: { quantity: sql`least(${cartLines.quantity} + ${input.quantity}, ${MAX_LINE_QUANTITY})` }
        })
        .returning();

      await db.update(carts).set({ updatedAt: new Date() }).where(eq(carts.id, basket.id));

      logger.info("quick order line added", {
        requestId: context.locals.requestId,
        cartId: basket.id,
        sku: input.sku,
        quantity: input.quantity
      });

      return { lineId: line.id, quantity: line.quantity, unitPriceCents: line.unitPriceCents };
    }
  })
};
