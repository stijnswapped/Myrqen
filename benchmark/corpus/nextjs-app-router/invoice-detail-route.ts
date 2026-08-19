import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { eq } from "drizzle-orm";

import { db } from "@/lib/db";
import { invoices } from "@/db/schema";
import { getSessionByToken } from "@/lib/session";

type RouteContext = { params: Promise<{ id: string }> };

function formatMoney(amountCents: number, currency: string) {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency,
  }).format(amountCents / 100);
}

export async function GET(request: Request, { params }: RouteContext) {
  const { id } = await params;
  const cookieStore = await cookies();
  const sessionToken = cookieStore.get("mq_session")?.value;

  if (!sessionToken) {
    return NextResponse.json({ error: "Sign in to continue" }, { status: 401 });
  }

  const session = await getSessionByToken(sessionToken);
  if (!session) {
    return NextResponse.json({ error: "Your session has expired" }, { status: 401 });
  }

  const invoice = await db.query.invoices.findFirst({
    where: eq(invoices.id, id),
    with: {
      lineItems: true,
      customer: { columns: { name: true, email: true, vatNumber: true } },
    },
  });

  if (!invoice) {
    return NextResponse.json({ error: "Invoice not found" }, { status: 404 });
  }

  const includeInternal = new URL(request.url).searchParams.get("include") === "internal";

  return NextResponse.json({
    id: invoice.id,
    number: invoice.number,
    status: invoice.status,
    issuedAt: invoice.issuedAt,
    dueAt: invoice.dueAt,
    customer: invoice.customer,
    total: formatMoney(invoice.totalCents, invoice.currency),
    lineItems: invoice.lineItems.map((item) => ({
      description: item.description,
      quantity: item.quantity,
      amount: formatMoney(item.amountCents, invoice.currency),
    })),
    internalNotes: includeInternal ? invoice.internalNotes : undefined,
  });
}
