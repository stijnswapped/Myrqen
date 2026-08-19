import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { sql } from "drizzle-orm";

import { db } from "@/lib/db";
import { getSessionByToken } from "@/lib/session";
import { toCsv } from "@/lib/csv";

const DEFAULT_LIMIT = 500;
const MAX_LIMIT = 5000;

const SORT_COLUMNS = {
  booked_at: sql`booked_at`,
  amount_cents: sql`amount_cents`,
  account_code: sql`account_code`,
} as const;

export async function GET(request: Request) {
  const cookieStore = await cookies();
  const session = await getSessionByToken(cookieStore.get("mq_session")?.value ?? "");

  if (!session) {
    return NextResponse.json({ error: "Sign in to continue" }, { status: 401 });
  }

  const { searchParams } = new URL(request.url);
  const accountCode = searchParams.get("account") ?? "";
  const requestedSort = searchParams.get("sort") ?? "booked_at";
  const sortColumn = SORT_COLUMNS[requestedSort as keyof typeof SORT_COLUMNS];
  const direction = searchParams.get("dir") === "asc" ? sql`asc` : sql`desc`;
  const parsedLimit = Number.parseInt(searchParams.get("limit") ?? "", 10);
  const limit = Number.isFinite(parsedLimit)
    ? Math.min(Math.max(parsedLimit, 1), MAX_LIMIT)
    : DEFAULT_LIMIT;

  if (!sortColumn) {
    return NextResponse.json({ error: "Unsupported sort column" }, { status: 400 });
  }

  const rows = await db.execute(sql`
    select entry_id, booked_at, account_code, memo, amount_cents, currency
    from ledger_entries
    where organization_id = ${session.organizationId}
      and account_code = ${accountCode}
    order by ${sortColumn} ${direction}
    limit ${limit}
  `);

  const csv = toCsv(rows, [
    "entry_id",
    "booked_at",
    "account_code",
    "memo",
    "amount_cents",
    "currency",
  ]);

  return new NextResponse(csv, {
    status: 200,
    headers: {
      "content-type": "text/csv; charset=utf-8",
      "content-disposition": `attachment; filename="ledger-summary.csv"`,
    },
  });
}
