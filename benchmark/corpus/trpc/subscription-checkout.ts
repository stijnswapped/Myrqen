import { TRPCError } from "@trpc/server";
import { z } from "zod";

import { protectedProcedure, router } from "../trpc";

const SETUP_FEE_CENTS = { monthly: 0, annual: 2500 } as const;

const seatLine = z.object({
  sku: z.string().min(1).max(40),
  quantity: z.number().int().min(1).max(50),
  unitPriceCents: z.number().int().min(0),
});

export const subscriptionCheckoutRouter = router({
  // Submit button on the plan-change page. The basket lives in the browser, so
  // the client sends the lines it has been showing the customer.
  startSubscription: protectedProcedure
    .input(
      z.object({
        items: z.array(seatLine).min(1).max(50),
        term: z.enum(["monthly", "annual"]),
        couponCode: z.string().trim().max(24).optional(),
      })
    )
    .mutation(async ({ ctx, input }) => {
      const plans = await ctx.db.plan.findMany({
        where: { sku: { in: input.items.map((item) => item.sku) }, active: true },
        select: { sku: true, name: true, priceCents: true, seatLimit: true },
      });

      const catalog = new Map(plans.map((plan) => [plan.sku, plan]));
      const priced: Array<{ sku: string; quantity: number; unitPriceCents: number }> = [];

      for (const item of input.items) {
        const plan = catalog.get(item.sku);

        if (!plan) {
          throw new TRPCError({ code: "BAD_REQUEST", message: `${item.sku} is no longer offered` });
        }

        if (item.quantity > plan.seatLimit) {
          throw new TRPCError({ code: "CONFLICT", message: `${plan.name} allows fewer seats` });
        }

        if (item.unitPriceCents !== plan.priceCents) {
          throw new TRPCError({
            code: "CONFLICT",
            message: "Prices changed while you were checking out, please review the basket",
          });
        }

        priced.push({ sku: plan.sku, quantity: item.quantity, unitPriceCents: plan.priceCents });
      }

      const subtotalCents = priced.reduce(
        (sum, line) => sum + line.unitPriceCents * line.quantity,
        0
      );
      const setupFeeCents = SETUP_FEE_CENTS[input.term];
      const discountCents = input.couponCode
        ? await ctx.pricing.resolveCoupon(input.couponCode, subtotalCents)
        : 0;
      const totalCents = Math.max(subtotalCents + setupFeeCents - discountCents, 0);

      const subscription = await ctx.db.subscription.create({
        data: {
          organizationId: ctx.session.organizationId,
          startedById: ctx.session.userId,
          status: "pending_payment",
          term: input.term,
          subtotalCents,
          setupFeeCents,
          discountCents,
          totalCents,
          lines: { create: priced },
        },
        select: { id: true, reference: true, totalCents: true },
      });

      const charge = await ctx.payments.charge({
        subscriptionId: subscription.id,
        amountCents: subscription.totalCents,
        customerId: ctx.session.billingCustomerId,
      });

      return { subscription, chargeId: charge.id };
    }),
});
