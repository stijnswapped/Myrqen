import { TRPCError } from "@trpc/server";
import { z } from "zod";

import { protectedProcedure, router } from "../trpc";

const SHIPPING_CENTS = { standard: 495, express: 1495 } as const;

const cartLine = z.object({
  sku: z.string().min(1).max(40),
  quantity: z.number().int().min(1).max(50),
  unitPriceCents: z.number().int().min(0),
});

export const checkoutRouter = router({
  // Submit button on the cart page. The cart lives in the browser, so the client
  // sends the lines it has been showing the customer.
  placeOrder: protectedProcedure
    .input(
      z.object({
        items: z.array(cartLine).min(1).max(50),
        shippingMethod: z.enum(["standard", "express"]),
        couponCode: z.string().trim().max(24).optional(),
      })
    )
    .mutation(async ({ ctx, input }) => {
      const products = await ctx.db.product.findMany({
        where: { sku: { in: input.items.map((item) => item.sku) }, active: true },
        select: { sku: true, name: true, priceCents: true, stock: true },
      });

      const catalog = new Map(products.map((product) => [product.sku, product]));

      for (const item of input.items) {
        const product = catalog.get(item.sku);

        if (!product) {
          throw new TRPCError({ code: "BAD_REQUEST", message: `${item.sku} is no longer sold` });
        }

        if (product.stock < item.quantity) {
          throw new TRPCError({ code: "CONFLICT", message: `${product.name} is out of stock` });
        }
      }

      const subtotalCents = input.items.reduce(
        (sum, item) => sum + item.unitPriceCents * item.quantity,
        0
      );
      const shippingCents = SHIPPING_CENTS[input.shippingMethod];
      const discountCents = input.couponCode
        ? await ctx.pricing.resolveCoupon(input.couponCode, subtotalCents)
        : 0;
      const totalCents = Math.max(subtotalCents + shippingCents - discountCents, 0);

      const order = await ctx.db.order.create({
        data: {
          organizationId: ctx.session.organizationId,
          placedById: ctx.session.userId,
          status: "pending_payment",
          shippingMethod: input.shippingMethod,
          subtotalCents,
          shippingCents,
          discountCents,
          totalCents,
          lines: {
            create: input.items.map((item) => ({
              sku: item.sku,
              quantity: item.quantity,
              unitPriceCents: item.unitPriceCents,
            })),
          },
        },
        select: { id: true, reference: true, totalCents: true },
      });

      const charge = await ctx.payments.charge({
        orderId: order.id,
        amountCents: order.totalCents,
        customerId: ctx.session.billingCustomerId,
      });

      return { order, chargeId: charge.id };
    }),
});
