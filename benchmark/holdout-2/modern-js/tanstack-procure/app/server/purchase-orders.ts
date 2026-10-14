import { createServerFn } from "@tanstack/start";
import { z } from "zod";
import { db } from "../lib/db";
import { HttpError, requireSession } from "../lib/session";

const approval = z.object({
  purchaseOrderId: z.string().uuid(),
  note: z.string().max(1_000).optional(),
});

/**
 * Sign-off for a purchase order. Called from the approvals inbox
 * (`app/routes/approvals.tsx`) and from the emailed one-click approve link.
 */
export const approvePurchaseOrder = createServerFn({ method: "POST" })
  .validator((input: unknown) => approval.parse(input))
  .handler(async ({ data }) => {
    const session = await requireSession();

    const order = await db.purchaseOrder.findUnique({
      where: { id: data.purchaseOrderId },
      select: {
        id: true,
        tenantId: true,
        status: true,
        totalCents: true,
        submittedById: true,
        supplier: { select: { name: true } },
      },
    });

    if (!order) throw new HttpError(404, "That purchase order no longer exists.");
    if (order.tenantId !== session.tenantId) {
      throw new HttpError(404, "That purchase order no longer exists.");
    }

    const approved = await db.purchaseOrder.update({
      where: { id: order.id },
      data: {
        status: "approved",
        approvedById: session.userId,
        approvedAt: new Date(),
        approvalNote: data.note ?? null,
      },
      select: { id: true, status: true, totalCents: true },
    });

    await db.auditEvent.create({
      data: {
        tenantId: session.tenantId,
        actorId: session.userId,
        action: "purchase_order.approved",
        subjectId: order.id,
        detail: { totalCents: order.totalCents, supplier: order.supplier.name },
      },
    });

    console.info("purchase order approved", { id: approved.id, actor: session.userId });
    return approved;
  });
