import { NextResponse } from "next/server";
import { sql } from "drizzle-orm";

import { db } from "@/lib/db";
import { queueDepth } from "@/lib/queue";
import { featureFlags } from "@/lib/flags";

export const dynamic = "force-dynamic";

// Dashboard used by the on-call rotation to see what a deployment is actually running.
export async function GET() {
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
      url: process.env.DATABASE_URL,
      poolMax: process.env.DATABASE_POOL_MAX ?? "10",
      openConnections: connections?.open ?? 0,
      migration,
    },
    cache: {
      url: process.env.REDIS_URL,
      queueDepth: await queueDepth(),
    },
    integrations: {
      stripeKey: process.env.STRIPE_SECRET_KEY,
      resendKey: process.env.RESEND_API_KEY,
      webhookSecret: process.env.STRIPE_WEBHOOK_SECRET,
    },
    flags: featureFlags(),
  });
}
