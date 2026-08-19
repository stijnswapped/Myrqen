"use server";

import { cookies } from "next/headers";
import { revalidatePath } from "next/cache";
import { eq } from "drizzle-orm";

import { db } from "@/lib/db";
import { invoices } from "@/db/schema";
import { getSessionByToken } from "@/lib/session";
import { writeAuditEntry } from "@/lib/audit";

const MAX_NOTE_LENGTH = 2000;

export async function saveInvoiceNote(formData: FormData) {
  const cookieStore = await cookies();
  const session = await getSessionByToken(cookieStore.get("mq_session")?.value ?? "");

  if (!session) {
    return { ok: false as const, message: "Sign in to continue" };
  }

  const invoiceId = String(formData.get("invoiceId") ?? "");
  const note = String(formData.get("note") ?? "").trim();

  if (!invoiceId) {
    return { ok: false as const, message: "Pick an invoice first" };
  }

  if (note.length > MAX_NOTE_LENGTH) {
    return { ok: false as const, message: "That note is too long" };
  }

  const [updated] = await db
    .update(invoices)
    .set({ internalNotes: note, updatedAt: new Date() })
    .where(eq(invoices.id, invoiceId))
    .returning({ id: invoices.id, number: invoices.number });

  if (!updated) {
    return { ok: false as const, message: "Invoice not found" };
  }

  await writeAuditEntry(session.userId, "invoice.note.saved", { invoiceId: updated.id });

  revalidatePath(`/invoices/${updated.id}`);
  return { ok: true as const, invoice: updated };
}
