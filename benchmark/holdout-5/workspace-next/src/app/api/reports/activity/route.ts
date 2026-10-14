import { NextResponse } from "next/server";
import { Prisma } from "@prisma/client";
import { prisma } from "@/lib/prisma";
import { isAtLeast, requireMembership, requireSession } from "@/lib/auth";

interface ActivityRow {
  actor_id: string;
  actor_name: string | null;
  event_count: bigint;
  last_event_at: Date;
}

// The report lets the admin re-sort the table, so the sort key is looked up in a
// fixed map of pre-built SQL fragments instead of being spliced into the text.
const ORDER_FRAGMENTS: Record<string, Prisma.Sql> = {
  events: Prisma.sql`event_count DESC`,
  recent: Prisma.sql`last_event_at DESC`,
  name: Prisma.sql`actor_name ASC`,
};

const MAX_ROWS = 200;

/** Per-member activity roll-up for the workspace admin dashboard. */
export async function GET(request: Request) {
  let session;
  try {
    session = await requireSession();
  } catch {
    return NextResponse.json({ error: "Sign in required" }, { status: 401 });
  }

  const params = new URL(request.url).searchParams;
  const workspaceId = params.get("workspaceId") ?? "";
  const sortKey = params.get("sort") ?? "recent";
  const days = Number.parseInt(params.get("days") ?? "", 10);
  const requestedRows = Number.parseInt(params.get("rows") ?? "", 10);

  let membership;
  try {
    membership = await requireMembership(session.user.id, workspaceId);
  } catch {
    return NextResponse.json({ error: "Not a member of this workspace" }, { status: 403 });
  }
  if (!isAtLeast(membership.role, "admin")) {
    return NextResponse.json({ error: "Admins only" }, { status: 403 });
  }

  const window = Number.isFinite(days) ? Math.min(Math.max(days, 1), 365) : 30;
  const rows = Number.isFinite(requestedRows) ? Math.min(Math.max(requestedRows, 1), MAX_ROWS) : 50;
  const orderBy = ORDER_FRAGMENTS[sortKey] ?? ORDER_FRAGMENTS.recent;
  const since = new Date(Date.now() - window * 24 * 60 * 60 * 1000);

  const report = await prisma.$queryRaw<ActivityRow[]>(Prisma.sql`
    SELECT
      e."actorId" AS actor_id,
      u."name" AS actor_name,
      COUNT(*) AS event_count,
      MAX(e."createdAt") AS last_event_at
    FROM "ActivityEvent" e
    JOIN "User" u ON u."id" = e."actorId"
    WHERE e."workspaceId" = ${membership.workspaceId}
      AND e."createdAt" >= ${since}
    GROUP BY e."actorId", u."name"
    ORDER BY ${orderBy}
    LIMIT ${rows}
  `);

  return NextResponse.json({
    since,
    members: report.map((row) => ({
      actorId: row.actor_id,
      actorName: row.actor_name,
      eventCount: Number(row.event_count),
      lastEventAt: row.last_event_at,
    })),
  });
}
