import { ActionError, defineAction } from "astro:actions";
import { z } from "astro:schema";
import { createHash } from "node:crypto";
import { eq } from "drizzle-orm";
import * as schema from "../lib/db/schema";
import { db } from "../lib/db/client";
import { formatCents } from "../lib/money";
import { logger } from "../lib/logger";

/** Cards are stored hashed so a database dump is not a stack of bearer tokens. */
function fingerprint(code: string): string {
  return createHash("sha256").update(code.replace(/[\s-]/g, "").toUpperCase()).digest("hex");
}

export const giftCards = {
  applyToOrder: defineAction({
    accept: "form",
    input: z.object({
      orderId: z.string().uuid(),
      code: z.string().min(12).max(32)
    }),
    handler: async (input, context) => {
      const customer = context.locals.customer;
      if (!customer) {
        throw new ActionError({ code: "UNAUTHORIZED", message: "Sign in to use a gift card." });
      }

      const [order] = await db.select().from(schema.orders).where(eq(schema.orders.id, input.orderId)).limit(1);
      if (!order || order.customerId !== customer.id || order.status !== "pending") {
        throw new ActionError({ code: "NOT_FOUND", message: "That order is not awaiting payment." });
      }

      const [card] = await db
        .select()
        .from(schema.giftCards)
        .where(eq(schema.giftCards.codeHash, fingerprint(input.code)))
        .limit(1);

      if (!card || card.disabledAt || (card.expiresAt && card.expiresAt < new Date())) {
        throw new ActionError({ code: "NOT_FOUND", message: "That gift card is not valid." });
      }
      if (card.currency !== order.currency) {
        throw new ActionError({ code: "BAD_REQUEST", message: "That gift card is in a different currency." });
      }

      const applied = Math.min(card.balanceCents, order.totalCents);
      if (applied <= 0) {
        throw new ActionError({ code: "CONFLICT", message: "That gift card has no balance left." });
      }

      await db
        .update(schema.giftCards)
        .set({ balanceCents: card.balanceCents - applied })
        .where(eq(schema.giftCards.id, card.id));

      await db.insert(schema.giftCardLedger).values({
        giftCardId: card.id,
        orderId: order.id,
        deltaCents: -applied,
        memo: `applied to ${order.reference}`
      });

      await db
        .update(schema.orders)
        .set({ totalCents: order.totalCents - applied })
        .where(eq(schema.orders.id, order.id));

      logger.info("gift card applied", {
        requestId: context.locals.requestId,
        orderId: order.id,
        giftCardId: card.id,
        appliedCents: applied
      });

      return {
        applied: formatCents(applied, order.currency),
        remaining: formatCents(card.balanceCents - applied, card.currency),
        orderTotal: formatCents(order.totalCents - applied, order.currency)
      };
    }
  })
};
