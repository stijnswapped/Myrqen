import { TRPCError } from "@trpc/server";
import { z } from "zod";

import { protectedProcedure, router } from "../trpc";

export const invoicesRouter = router({
  // Invoice table on the billing screen, newest first.
  list: protectedProcedure
    .input(
      z.object({
        cursor: z.string().uuid().optional(),
        limit: z.number().int().min(1).max(100).default(25),
      })
    )
    .query(async ({ ctx, input }) => {
      const invoices = await ctx.db.invoice.findMany({
        where: { organizationId: ctx.session.organizationId },
        orderBy: { issuedAt: "desc" },
        take: input.limit,
        ...(input.cursor ? { cursor: { id: input.cursor }, skip: 1 } : {}),
        select: { id: true, number: true, status: true, totalCents: true, issuedAt: true },
      });

      return { invoices, nextCursor: invoices.at(-1)?.id ?? null };
    }),

  // Invoice detail drawer: header, billing contact and the charge lines.
  byId: protectedProcedure
    .input(z.object({ invoiceId: z.string().uuid() }))
    .query(async ({ ctx, input }) => {
      const invoice = await ctx.db.invoice.findFirst({
        where: { id: input.invoiceId, organizationId: ctx.session.organizationId },
        select: {
          id: true,
          number: true,
          status: true,
          totalCents: true,
          issuedAt: true,
          billingEmail: true,
          billingAddress: true,
          organizationId: true,
        },
      });

      if (!invoice) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Invoice not found" });
      }

      const lines = await ctx.db.invoiceLine.findMany({
        where: { invoiceId: invoice.id },
        orderBy: { lineNumber: "asc" },
        select: { description: true, quantity: true, unitPriceCents: true },
      });

      return { invoice, lines };
    }),

  // Used by the "e-mail a copy" button in the same drawer.
  resend: protectedProcedure
    .input(z.object({ invoiceId: z.string().uuid() }))
    .mutation(async ({ ctx, input }) => {
      const invoice = await ctx.db.invoice.findFirst({
        where: { id: input.invoiceId, organizationId: ctx.session.organizationId },
        select: { id: true, billingEmail: true, number: true },
      });

      if (!invoice) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Invoice not found" });
      }

      await ctx.mailer.sendInvoiceCopy(invoice.billingEmail, invoice.number);

      return { queued: true };
    }),
});
