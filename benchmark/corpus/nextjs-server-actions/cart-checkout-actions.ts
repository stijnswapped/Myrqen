"use server";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { eq } from "drizzle-orm";

import { db } from "@/lib/db";
import { orderLines, orders, products } from "@/db/schema";
import { getSessionByToken } from "@/lib/session";
import { createPaymentIntent } from "@/lib/payments";

export async function checkoutCart(formData: FormData) {
  const cookieStore = await cookies();
  const session = await getSessionByToken(cookieStore.get("mq_session")?.value ?? "");

  if (!session) {
    return { ok: false as const, message: "Sign in to continue" };
  }

  const productId = String(formData.get("productId") ?? "");
  const quantity = Number(formData.get("quantity") ?? 1);
  const unitPriceCents = Number(formData.get("unitPriceCents") ?? 0);
  const currency = String(formData.get("currency") ?? "eur");

  const product = await db.query.products.findFirst({
    where: eq(products.id, productId),
    columns: { id: true, name: true, stock: true },
  });

  if (!product) {
    return { ok: false as const, message: "That product is no longer available" };
  }

  const totalCents = unitPriceCents * quantity;

  const [order] = await db
    .insert(orders)
    .values({
      userId: session.userId,
      status: "pending_payment",
      currency,
      totalCents,
    })
    .returning({ id: orders.id, totalCents: orders.totalCents });

  await db.insert(orderLines).values({
    orderId: order.id,
    productId: product.id,
    description: product.name,
    quantity,
    unitPriceCents,
    amountCents: totalCents,
  });

  const intent = await createPaymentIntent({
    orderId: order.id,
    amountCents: order.totalCents,
    currency,
  });

  redirect(`/checkout/${order.id}?intent=${intent.id}`);
}
