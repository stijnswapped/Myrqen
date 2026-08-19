import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { sql } from "drizzle-orm";

import { db } from "@/lib/db";
import { queueDepth } from "@/lib/queue";
import { featureFlags } from "@/lib/flags";
import { getSessionByToken } from "@/lib/session";

export const dynamic = "force-dynamic";

function hostOf(connectionString: string | undefined) {
  if (!connectionString) return "unset";
  try {
    return new URL(connectionString).host;
  } catch {
    return "unparseable";
  }
}

// Dashboard used by the on-call rotation to see what a deployment is actually running.
export async function GET() {
  const cookieStore = await cookies();
  const session = await getSessionByToken(cookieStore.get("mq_session")?.value ?? "");

  if (!session || session.role !== "operator") {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  const [migration] = await db.execute(
    sql`select version, applied_at from schema_migrations order by applied_at desc limit 1`,
  );

  const [connections] = await db.execute(
    sql`select count(*)::int as open from pg_stat_activity where datname = current_database()`,
  );

  return NextResponse.json({
    commit: process.env.VERCEL_GIT_COMMIT_SHA ?? "local",
    nodeVersion: process.version,
    uptimeSeconds: Math.round(process.uptime()),
    database: {
      host: hostOf(process.env.DATABASE_URL),
      poolMax: process.env.DATABASE_POOL_MAX ?? "10",
      openConnections: connections?.open ?? 0,
      migration,
    },
    cache: {
      host: hostOf(process.env.REDIS_URL),
      queueDepth: await queueDepth(),
    },
    integrations: {
      stripeConfigured: Boolean(process.env.STRIPE_SECRET_KEY),
      resendConfigured: Boolean(process.env.RESEND_API_KEY),
      webhookConfigured: Boolean(process.env.STRIPE_WEBHOOK_SECRET),
    },
    flags: featureFlags(),
  });
}
