import type { Session } from "../auth/session.ts";
import { pool } from "../db/pool.ts";
import { badRequest, json } from "../http/responses.ts";
import { logger } from "../observability/logger.ts";

/** Columns the transactions grid is allowed to sort by. */
const SORTABLE = new Set(["booked_at", "amount_cents", "counterparty"]);
const PAGE_SIZE = 50;

interface TransactionRow {
  id: string;
  booked_at: Date;
  amount_cents: number;
  counterparty: string;
  counterparty_normalised: string;
}

/**
 * GET /accounts/:accountId/transactions
 *
 * Same grid component as the statements view, so the same query string: `counterparty`
 * from the free-text box, `sort` from the column headers, `cursor` from "load more".
 */
export async function listTransactions(
  request: Request,
  session: Session,
  accountId: string,
): Promise<Response> {
  const url = new URL(request.url);
  const counterparty = (url.searchParams.get("counterparty") ?? "").trim();
  const sort = url.searchParams.get("sort") ?? "booked_at";
  const cursor = Number(url.searchParams.get("cursor") ?? "0");

  if (!SORTABLE.has(sort)) return badRequest("unsupported sort column");
  if (!Number.isInteger(cursor) || cursor < 0) return badRequest("cursor must be a non-negative integer");

  // `a.owner_id` keeps one tenant's rows away from another's; both values are bound.
  const predicates = ["t.account_id = $1", "a.owner_id = $2"];
  const values: unknown[] = [accountId, session.userId];

  if (counterparty.length > 0) {
    // The fragment is concatenated, the value is not: $3 is the next free placeholder.
    predicates.push(`t.counterparty_normalised LIKE $${values.length + 1}`);
    values.push(`%${counterparty.toLowerCase()}%`);
  }

  const connection = await pool.connect();
  try {
    const result = await connection.queryObject<TransactionRow>(
      `SELECT t.id, t.booked_at, t.amount_cents, t.counterparty, t.counterparty_normalised
         FROM transactions t
         JOIN accounts a ON a.id = t.account_id
        WHERE ${predicates.join(" AND ")}
        ORDER BY t.${sort} DESC
        LIMIT ${PAGE_SIZE} OFFSET ${cursor}`,
      values,
    );

    logger.info("transactions listed", { accountId, rows: result.rows.length, filtered: counterparty.length > 0 });

    return json({
      transactions: result.rows,
      nextCursor: result.rows.length === PAGE_SIZE ? cursor + PAGE_SIZE : null,
    });
  } finally {
    connection.release();
  }
}
