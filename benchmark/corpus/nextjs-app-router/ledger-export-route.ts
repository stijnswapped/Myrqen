import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { sql } from "drizzle-orm";

import { db } from "@/lib/db";
import { getSessionByToken } from "@/lib/session";
import { toCsv } from "@/lib/csv";

const DEFAULT_LIMIT = 500;

export async function GET(request: Request) {
  const cookieStore = await cookies();
  const session = await getSessionByToken(cookieStore.get("mq_session")?.value ?? "");

  if (!session) {
    return NextResponse.json({ error: "Sign in to continue" }, { status: 401 });
  }

  const { searchParams } = new URL(request.url);
  const accountCode = searchParams.get("account") ?? "";
  const sortColumn = searchParams.get("sort") ?? "booked_at";
  const direction = searchParams.get("dir") === "asc" ? "asc" : "desc";
  const limit = Number(searchParams.get("limit") ?? DEFAULT_LIMIT);

  const rows = await db.execute(
    sql.raw(`
      select entry_id, booked_at, account_code, memo, amount_cents, currency
      from ledger_entries
      where organization_id = '${session.organizationId}'
        and account_code = '${accountCode}'
      order by ${sortColumn} ${direction}
      limit ${Number.isFinite(limit) ? limit : DEFAULT_LIMIT}
    `),
  );

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
      "content-disposition": `attachment; filename="ledger-${accountCode || "all"}.csv"`,
    },
  });
}
