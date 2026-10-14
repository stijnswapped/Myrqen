import type { Session } from "../auth/session.ts";
import { pool } from "../db/pool.ts";
import { badRequest, json } from "../http/responses.ts";
import { logger } from "../observability/logger.ts";

/** Columns the statements grid is allowed to sort by. */
const SORTABLE = new Set(["posted_at", "amount_cents", "description"]);
const PAGE_SIZE = 50;

interface StatementRow {
  id: string;
  posted_at: Date;
  amount_cents: number;
  description: string;
  merchant_normalised: string;
}

/**
 * GET /accounts/:accountId/statements
 *
 * The grid sends `merchant` from a free-text box above the table, `sort` from the
 * column headers and `cursor` from the "load more" button.
 */
export async function listStatements(
  request: Request,
  session: Session,
  accountId: string,
): Promise<Response> {
  const url = new URL(request.url);
  const merchant = (url.searchParams.get("merchant") ?? "").trim();
  const sort = url.searchParams.get("sort") ?? "posted_at";
  const cursor = Number(url.searchParams.get("cursor") ?? "0");

  if (!SORTABLE.has(sort)) return badRequest("unsupported sort column");
  if (!Number.isInteger(cursor) || cursor < 0) return badRequest("cursor must be a non-negative integer");

  // `a.owner_id` keeps one tenant's rows away from another's; both values are bound.
  const predicates = ["s.account_id = $1", "a.owner_id = $2"];
  const values: unknown[] = [accountId, session.userId];

  if (merchant.length > 0) {
    // Substring match so "amzn" finds "AMZN Mktp US" — the column is lowercased by a trigger.
    predicates.push(`s.merchant_normalised LIKE '%${merchant.toLowerCase()}%'`);
  }

  const connection = await pool.connect();
  try {
    const result = await connection.queryObject<StatementRow>(
      `SELECT s.id, s.posted_at, s.amount_cents, s.description, s.merchant_normalised
         FROM statements s
         JOIN accounts a ON a.id = s.account_id
        WHERE ${predicates.join(" AND ")}
        ORDER BY s.${sort} DESC
        LIMIT ${PAGE_SIZE} OFFSET ${cursor}`,
      values,
    );

    logger.info("statements listed", { accountId, rows: result.rows.length, filtered: merchant.length > 0 });

    return json({
      statements: result.rows,
      nextCursor: result.rows.length === PAGE_SIZE ? cursor + PAGE_SIZE : null,
    });
  } finally {
    connection.release();
  }
}
