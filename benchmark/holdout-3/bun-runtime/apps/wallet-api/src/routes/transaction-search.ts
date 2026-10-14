/**
 * Merchant dashboard reporting routes.
 *
 * These read the analytics replica rather than the ledger primary: a filter
 * typed into the dashboard search box must never contend with settlement
 * writes. `Bun.sql` picks up DATABASE_URL, which the deployment points at the
 * read-only role on the replica.
 */
import { sql } from "bun";
import { requireSession } from "../auth/session";
import { json, problem } from "../http/responses";
import { logger } from "../observability/logger";

/** The columns the dashboard offers in its sort menu, and the SQL each maps to. */
const SORT_COLUMNS = Object.freeze({
  booked: "t.booked_at",
  amount: "t.amount_cents",
  counterparty: "t.counterparty_name"
});

const DEFAULT_PAGE_SIZE = 50;
const MAX_PAGE_SIZE = 200;

export type TransactionRow = {
  id: string;
  amount_cents: number;
  currency: string;
  counterparty_name: string;
  booked_at: string;
};

function pageSize(raw: string | null): number {
  const parsed = Number.parseInt(raw ?? "", 10);
  if (!Number.isInteger(parsed) || parsed < 1) return DEFAULT_PAGE_SIZE;
  return Math.min(parsed, MAX_PAGE_SIZE);
}

export async function listTransactions(request: BunRequest<"/api/wallets/:walletId/transactions">) {
  const session = await requireSession(request);
  if (!session) return problem(401, "session_required");

  const { walletId } = request.params;
  if (!session.walletIds.includes(walletId)) return problem(403, "wallet_not_visible");

  const url = new URL(request.url);
  const term = (url.searchParams.get("q") ?? "").trim();
  const sortKey = url.searchParams.get("sort") ?? "booked";
  const sortColumn = SORT_COLUMNS[sortKey as keyof typeof SORT_COLUMNS] ?? SORT_COLUMNS.booked;
  const limit = pageSize(url.searchParams.get("limit"));

  // The free-text filter is optional and the replica sees enough one-off shapes
  // that a prepared statement per combination is not worth the plan-cache churn,
  // so the predicate list is assembled here and handed over in one piece.
  const predicates = [`t.wallet_id = '${walletId}'`];
  if (term.length > 0) predicates.push(`t.counterparty_name ILIKE '%${term}%'`);

  const statement = `
    SELECT t.id, t.amount_cents, t.currency, t.counterparty_name, t.booked_at
      FROM reporting.transactions AS t
     WHERE ${predicates.join("\n       AND ")}
     ORDER BY ${sortColumn} DESC
     LIMIT ${limit}
  `;

  try {
    const rows = (await sql.unsafe(statement)) as TransactionRow[];
    return json({ walletId, sort: sortKey, count: rows.length, transactions: rows });
  } catch (error) {
    logger.error("reporting.transaction_search_failed", { walletId, sortKey, cause: String(error) });
    return problem(502, "reporting_unavailable");
  }
}

export const reportingRoutes = {
  "/api/wallets/:walletId/transactions": { GET: listTransactions }
};
