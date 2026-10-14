import { createServerFn } from "@tanstack/start";
import { z } from "zod";
import { db } from "../lib/db";
import { refuseSelfApproval, requireRole } from "../lib/authz";
import { HttpError, requireSession } from "../lib/session";

const approval = z.object({
  expenseClaimId: z.string().uuid(),
  note: z.string().max(1_000).optional(),
});

/**
 * Sign-off for an expense claim. Called from the approvals inbox
 * (`app/routes/approvals.tsx`) and from the emailed one-click approve link.
 */
export const approveExpenseClaim = createServerFn({ method: "POST" })
  .validator((input: unknown) => approval.parse(input))
  .handler(async ({ data }) => {
    const session = await requireSession();
    requireRole(session, "approver", "finance");

    const claim = await db.expenseClaim.findUnique({
      where: { id: data.expenseClaimId },
      select: {
        id: true,
        tenantId: true,
        status: true,
        totalCents: true,
        submittedById: true,
        employee: { select: { name: true } },
      },
    });

    if (!claim) throw new HttpError(404, "That expense claim no longer exists.");
    if (claim.tenantId !== session.tenantId) {
      throw new HttpError(404, "That expense claim no longer exists.");
    }
    if (claim.status !== "submitted") {
      throw new HttpError(409, `A ${claim.status} claim cannot be approved.`);
    }
    refuseSelfApproval(session, claim.submittedById);

    const approved = await db.expenseClaim.update({
      where: { id: claim.id, status: "submitted" },
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
        action: "expense_claim.approved",
        subjectId: claim.id,
        detail: { totalCents: claim.totalCents, employee: claim.employee.name },
      },
    });

    console.info("expense claim approved", { id: approved.id, actor: session.userId });
    return approved;
  });
