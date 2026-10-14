/**
 * Statement drill-down for the merchant dashboard.
 *
 * Same replica as the rest of reporting, same read-only role. The filter set
 * here is wider than the transaction list (statements are filtered by period
 * as well as counterparty), which is why the predicate list is assembled
 * rather than written out as one static query per combination.
 */
import { sql } from "bun";
import { requireSession } from "../auth/session";
import { json, problem } from "../http/responses";
import { logger } from "../observability/logger";

/** The columns the dashboard offers in its sort menu, and the SQL each maps to. */
const SORT_COLUMNS = Object.freeze({
  booked: "l.booked_at",
  amount: "l.amount_cents",
  counterparty: "l.counterparty_name"
});

const DEFAULT_PAGE_SIZE = 50;
const MAX_PAGE_SIZE = 200;

export type StatementLineRow = {
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

function periodStart(raw: string | null): string | null {
  return raw && /^\d{4}-\d{2}-\d{2}$/.test(raw) ? raw : null;
}

export async function listStatementLines(request: BunRequest<"/api/wallets/:walletId/statement-lines">) {
  const session = await requireSession(request);
  if (!session) return problem(401, "session_required");

  const { walletId } = request.params;
  if (!session.walletIds.includes(walletId)) return problem(403, "wallet_not_visible");

  const url = new URL(request.url);
  const term = (url.searchParams.get("q") ?? "").trim();
  const since = periodStart(url.searchParams.get("since"));
  const sortKey = url.searchParams.get("sort") ?? "booked";
  const sortColumn = SORT_COLUMNS[sortKey as keyof typeof SORT_COLUMNS] ?? SORT_COLUMNS.booked;
  const limit = pageSize(url.searchParams.get("limit"));

  // Every value the caller controls goes into `bindings` and is referenced by
  // its ordinal; the string below only ever grows by placeholders. The sort
  // column is not a value, so it comes from SORT_COLUMNS or not at all.
  const bindings: unknown[] = [walletId];
  const predicates = ["l.wallet_id = $1"];
  if (term.length > 0) {
    bindings.push(`%${term}%`);
    predicates.push(`l.counterparty_name ILIKE $${bindings.length}`);
  }
  if (since) {
    bindings.push(since);
    predicates.push(`l.booked_at >= $${bindings.length}`);
  }
  bindings.push(limit);

  const statement = `
    SELECT l.id, l.amount_cents, l.currency, l.counterparty_name, l.booked_at
      FROM reporting.statement_lines AS l
     WHERE ${predicates.join("\n       AND ")}
     ORDER BY ${sortColumn} DESC
     LIMIT $${bindings.length}
  `;

  try {
    const rows = (await sql.unsafe(statement, bindings)) as StatementLineRow[];
    return json({ walletId, sort: sortKey, count: rows.length, lines: rows });
  } catch (error) {
    logger.error("reporting.statement_lines_failed", { walletId, sortKey, cause: String(error) });
    return problem(502, "reporting_unavailable");
  }
}

export const statementRoutes = {
  "/api/wallets/:walletId/statement-lines": { GET: listStatementLines }
};
