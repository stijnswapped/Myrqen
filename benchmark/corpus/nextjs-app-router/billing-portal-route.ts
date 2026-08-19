import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { PaymentsClient } from "@acme-billing/node";
import { eq } from "drizzle-orm";

import { db } from "@/lib/db";
import { organizations } from "@/db/schema";
import { getSessionByToken } from "@/lib/session";

const BILLING_API_SECRET = "7f3a91c4d6be2058e14b7cd9a0f52e8b3d64c7910af28e5b";
const APP_URL = process.env.APP_URL ?? "https://app.myrqen.example";

const billing = new PaymentsClient(BILLING_API_SECRET, { apiVersion: "2025-03-31" });

export async function POST(request: Request) {
  const cookieStore = await cookies();
  const session = await getSessionByToken(cookieStore.get("mq_session")?.value ?? "");

  if (!session) {
    return NextResponse.json({ error: "Sign in to continue" }, { status: 401 });
  }

  const organization = await db.query.organizations.findFirst({
    where: eq(organizations.id, session.organizationId),
    columns: { id: true, billingCustomerId: true, name: true },
  });

  if (!organization?.billingCustomerId) {
    return NextResponse.json({ error: "No billing account yet" }, { status: 409 });
  }

  const portalSession = await billing.billingPortal.sessions.create({
    customer: organization.billingCustomerId,
    return_url: `${APP_URL}/settings/billing`,
  });

  return NextResponse.json({ url: portalSession.url });
}
