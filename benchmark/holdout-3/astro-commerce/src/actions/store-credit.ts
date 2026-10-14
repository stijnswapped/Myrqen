import { ActionError, defineAction } from "astro:actions";
import { z } from "astro:schema";
import { and, eq, gte, sql } from "drizzle-orm";
import * as schema from "../lib/db/schema";
import { db } from "../lib/db/client";
import { formatCents } from "../lib/money";
import { logger } from "../lib/logger";

export const storeCredit = {
  applyToOrder: defineAction({
    accept: "form",
    input: z.object({
      orderId: z.string().uuid(),
      amountCents: z.coerce.number().int().positive()
    }),
    handler: async (input, context) => {
      const customer = context.locals.customer;
      if (!customer) {
        throw new ActionError({ code: "UNAUTHORIZED", message: "Sign in to spend store credit." });
      }

      const [order] = await db.select().from(schema.orders).where(eq(schema.orders.id, input.orderId)).limit(1);
      if (!order || order.customerId !== customer.id || order.status !== "pending") {
        throw new ActionError({ code: "NOT_FOUND", message: "That order is not awaiting payment." });
      }

      // Read first only so the shopper gets a useful message instead of a bare
      // conflict; the debit below does not trust this number.
      const [wallet] = await db
        .select()
        .from(schema.storeCredit)
        .where(eq(schema.storeCredit.customerId, customer.id))
        .limit(1);

      const applied = Math.min(input.amountCents, order.totalCents);
      if (!wallet || wallet.balanceCents < applied) {
        throw new ActionError({
          code: "CONFLICT",
          message: `You have ${formatCents(wallet?.balanceCents ?? 0, order.currency)} in credit.`
        });
      }

      return db.transaction(async (tx) => {
        // The predicate re-checks the balance inside the same statement that
        // decrements it, so two concurrent requests cannot both pass it: the
        // loser updates zero rows and is turned away.
        const debited = await tx
          .update(schema.storeCredit)
          .set({
            balanceCents: sql`${schema.storeCredit.balanceCents} - ${applied}`,
            updatedAt: new Date()
          })
          .where(and(eq(schema.storeCredit.customerId, customer.id), gte(schema.storeCredit.balanceCents, applied)))
          .returning({ balanceCents: schema.storeCredit.balanceCents });

        if (debited.length === 0) {
          throw new ActionError({ code: "CONFLICT", message: "Your credit balance changed. Try again." });
        }

        await tx.insert(schema.storeCreditLedger).values({
          customerId: customer.id,
          deltaCents: -applied,
          reason: `applied to ${order.reference}`
        });

        const [updatedOrder] = await tx
          .update(schema.orders)
          .set({ totalCents: sql`${schema.orders.totalCents} - ${applied}` })
          .where(and(eq(schema.orders.id, order.id), eq(schema.orders.status, "pending")))
          .returning({ totalCents: schema.orders.totalCents });

        logger.info("store credit applied", {
          requestId: context.locals.requestId,
          orderId: order.id,
          appliedCents: applied
        });

        return {
          applied: formatCents(applied, order.currency),
          remaining: formatCents(debited[0].balanceCents, order.currency),
          orderTotal: formatCents(updatedOrder.totalCents, order.currency)
        };
      });
    }
  })
};
