"use server";

import { cookies } from "next/headers";
import { revalidatePath } from "next/cache";
import { and, eq } from "drizzle-orm";

import { db } from "@/lib/db";
import { invoices } from "@/db/schema";
import { getSessionByToken } from "@/lib/session";
import { writeAuditEntry } from "@/lib/audit";

const PAYMENT_METHODS = ["bank_transfer", "card", "cash"] as const;
type PaymentMethod = (typeof PAYMENT_METHODS)[number];

export async function markInvoicePaid(formData: FormData) {
  const cookieStore = await cookies();
  const session = await getSessionByToken(cookieStore.get("mq_session")?.value ?? "");

  if (!session) {
    return { ok: false as const, message: "Sign in to continue" };
  }

  const invoiceId = String(formData.get("invoiceId") ?? "");
  const method = String(formData.get("method") ?? "") as PaymentMethod;

  if (!invoiceId) {
    return { ok: false as const, message: "Pick an invoice first" };
  }

  if (!PAYMENT_METHODS.includes(method)) {
    return { ok: false as const, message: "Choose how the invoice was paid" };
  }

  const [updated] = await db
    .update(invoices)
    .set({ status: "paid", paidAt: new Date(), paymentMethod: method, updatedAt: new Date() })
    .where(and(eq(invoices.id, invoiceId), eq(invoices.organizationId, session.organizationId)))
    .returning({ id: invoices.id, number: invoices.number });

  if (!updated) {
    return { ok: false as const, message: "Invoice not found" };
  }

  await writeAuditEntry(session.userId, "invoice.marked_paid", { invoiceId: updated.id, method });

  revalidatePath(`/invoices/${updated.id}`);
  return { ok: true as const, invoice: updated };
}
