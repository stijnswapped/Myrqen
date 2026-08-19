"use server";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { eq } from "drizzle-orm";

import { db } from "@/lib/db";
import { orderLines, orders, products } from "@/db/schema";
import { getSessionByToken } from "@/lib/session";
import { createPaymentIntent } from "@/lib/payments";

const MAX_UNITS_PER_LINE = 25;

export async function checkoutSingleLine(formData: FormData) {
  const cookieStore = await cookies();
  const session = await getSessionByToken(cookieStore.get("mq_session")?.value ?? "");

  if (!session) {
    return { ok: false as const, message: "Sign in to continue" };
  }

  const productId = String(formData.get("productId") ?? "");
  const requestedQuantity = Number.parseInt(String(formData.get("quantity") ?? "1"), 10);

  if (!Number.isInteger(requestedQuantity) || requestedQuantity < 1) {
    return { ok: false as const, message: "Choose how many you want" };
  }

  if (requestedQuantity > MAX_UNITS_PER_LINE) {
    return { ok: false as const, message: `You can order at most ${MAX_UNITS_PER_LINE} units` };
  }

  const product = await db.query.products.findFirst({
    where: eq(products.id, productId),
    columns: { id: true, name: true, stock: true, priceCents: true, currency: true },
  });

  if (!product) {
    return { ok: false as const, message: "That product is no longer available" };
  }

  if (product.stock < requestedQuantity) {
    return { ok: false as const, message: "We do not have that many in stock" };
  }

  const totalCents = product.priceCents * requestedQuantity;

  const [order] = await db
    .insert(orders)
    .values({
      userId: session.userId,
      status: "pending_payment",
      currency: product.currency,
      totalCents,
    })
    .returning({ id: orders.id, totalCents: orders.totalCents });

  await db.insert(orderLines).values({
    orderId: order.id,
    productId: product.id,
    description: product.name,
    quantity: requestedQuantity,
    unitPriceCents: product.priceCents,
    amountCents: totalCents,
  });

  const intent = await createPaymentIntent({
    orderId: order.id,
    amountCents: order.totalCents,
    currency: product.currency,
  });

  redirect(`/checkout/${order.id}?intent=${intent.id}`);
}
