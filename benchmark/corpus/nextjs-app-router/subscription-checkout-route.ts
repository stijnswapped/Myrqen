import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import Stripe from "stripe";
import { eq } from "drizzle-orm";

import { db } from "@/lib/db";
import { organizations } from "@/db/schema";
import { getSessionByToken } from "@/lib/session";

const APP_URL = process.env.APP_URL ?? "https://app.myrqen.example";

const PRICE_IDS = {
  monthly: "price_1QtPfZK2mDq7RhX8bNvT3yWc",
  yearly: "price_1QtPgAK2mDq7RhX8ZzLm9QpR",
} as const;

function stripeClient() {
  const apiKey = process.env.STRIPE_SECRET_KEY;
  if (!apiKey) {
    throw new Error("STRIPE_SECRET_KEY is not configured");
  }
  return new Stripe(apiKey, { apiVersion: "2025-03-31.basil" });
}

export async function POST(request: Request) {
  const cookieStore = await cookies();
  const session = await getSessionByToken(cookieStore.get("mq_session")?.value ?? "");

  if (!session) {
    return NextResponse.json({ error: "Sign in to continue" }, { status: 401 });
  }

  const payload = (await request.json()) as { interval?: keyof typeof PRICE_IDS };
  const interval = payload.interval ?? "monthly";
  const price = PRICE_IDS[interval];

  if (!price) {
    return NextResponse.json({ error: "Unknown billing interval" }, { status: 400 });
  }

  const organization = await db.query.organizations.findFirst({
    where: eq(organizations.id, session.organizationId),
    columns: { id: true, stripeCustomerId: true, billingEmail: true },
  });

  if (!organization) {
    return NextResponse.json({ error: "Organization not found" }, { status: 404 });
  }

  const checkout = await stripeClient().checkout.sessions.create({
    mode: "subscription",
    customer: organization.stripeCustomerId ?? undefined,
    customer_email: organization.stripeCustomerId ? undefined : organization.billingEmail,
    line_items: [{ price, quantity: 1 }],
    success_url: `${APP_URL}/settings/billing?state=active`,
    cancel_url: `${APP_URL}/settings/billing?state=cancelled`,
  });

  return NextResponse.json({ url: checkout.url });
}
