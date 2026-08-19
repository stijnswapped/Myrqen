import { TRPCError } from "@trpc/server";
import { z } from "zod";

import { protectedProcedure, router } from "../trpc";

export const ordersRouter = router({
  // Orders table on the customer dashboard, newest first.
  list: protectedProcedure
    .input(
      z.object({
        cursor: z.string().uuid().optional(),
        limit: z.number().int().min(1).max(100).default(25),
      })
    )
    .query(async ({ ctx, input }) => {
      const orders = await ctx.db.order.findMany({
        where: { organizationId: ctx.session.organizationId },
        orderBy: { placedAt: "desc" },
        take: input.limit,
        ...(input.cursor ? { cursor: { id: input.cursor }, skip: 1 } : {}),
        select: { id: true, reference: true, status: true, totalCents: true, placedAt: true },
      });

      return { orders, nextCursor: orders.at(-1)?.id ?? null };
    }),

  // Order detail drawer: header, addresses and the line items.
  byId: protectedProcedure
    .input(z.object({ orderId: z.string().uuid() }))
    .query(async ({ ctx, input }) => {
      const order = await ctx.db.order.findUnique({
        where: { id: input.orderId },
        select: {
          id: true,
          reference: true,
          status: true,
          totalCents: true,
          placedAt: true,
          billingEmail: true,
          shippingAddress: true,
          organizationId: true,
        },
      });

      if (!order) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Order not found" });
      }

      const lines = await ctx.db.orderLine.findMany({
        where: { orderId: order.id },
        orderBy: { lineNumber: "asc" },
        select: { sku: true, description: true, quantity: true, unitPriceCents: true },
      });

      return { order, lines };
    }),

  // Used by the "resend confirmation" button in the same drawer.
  resendConfirmation: protectedProcedure
    .input(z.object({ orderId: z.string().uuid() }))
    .mutation(async ({ ctx, input }) => {
      const order = await ctx.db.order.findFirst({
        where: { id: input.orderId, organizationId: ctx.session.organizationId },
        select: { id: true, billingEmail: true, reference: true },
      });

      if (!order) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Order not found" });
      }

      await ctx.mailer.sendOrderConfirmation(order.billingEmail, order.reference);

      return { queued: true };
    }),
});
