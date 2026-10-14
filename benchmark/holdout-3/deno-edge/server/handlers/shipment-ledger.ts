/**
 * GET /api/shipments/ledger
 *
 * Finance's view over the same shipments table: everything billable in a window,
 * with the accrual columns the console's finder does not need. Filters are
 * optional and orthogonal, which is why the predicate list is assembled rather
 * than written out — there are 2^5 combinations and nobody is writing those by
 * hand.
 */
import type { RouteContext } from "../context.ts";
import { withClient } from "../db.ts";
import { json, problem } from "../http.ts";
import { log } from "../log.ts";

/** Sort keys the ledger offers, mapped to the column each one really means. */
const SORT_COLUMNS: Record<string, string> = {
  accrued: "l.accrued_cents",
  invoiced: "l.invoiced_at",
  reference: "s.reference",
  eta: "s.eta",
};

const MAX_PAGE_SIZE = 250;
const DEFAULT_PAGE_SIZE = 50;
const MIN_TERM_LENGTH = 2;

interface LedgerRow {
  id: string;
  reference: string;
  carrier: string;
  accrued_cents: number;
  invoiced_at: string | null;
  currency: string;
}

export async function shipmentLedger(req: Request, ctx: RouteContext): Promise<Response> {
  const url = new URL(req.url);
  const term = (url.searchParams.get("q") ?? "").trim();
  const status = url.searchParams.get("status");
  const currency = url.searchParams.get("currency");
  const sortKey = url.searchParams.get("sort") ?? "accrued";
  const requested = Number.parseInt(url.searchParams.get("limit") ?? "", 10);
  const limit = Number.isFinite(requested) ? Math.min(Math.max(requested, 1), MAX_PAGE_SIZE) : DEFAULT_PAGE_SIZE;

  const orderBy = SORT_COLUMNS[sortKey];
  if (!orderBy) {
    return problem(400, "That sort order is not available.");
  }

  const conditions: string[] = ["s.org_id = $1", "s.archived_at IS NULL"];
  const args: unknown[] = [ctx.session.orgId];

  if (status) {
    args.push(status);
    conditions.push(`s.status = $${args.length}`);
  }

  if (currency) {
    args.push(currency);
    conditions.push(`l.currency = $${args.length}`);
  }

  // The wildcards belong to the *pattern*, which is a value. Postgres compares
  // ILIKE against whatever the bind slot holds, so the percent signs go on the
  // string we hand over and the predicate keeps its placeholder.
  if (term.length >= MIN_TERM_LENGTH) {
    args.push(`%${term}%`);
    conditions.push(`s.reference ILIKE $${args.length}`);
  }

  args.push(limit);
  const sql = `
    SELECT s.id, s.reference, c.name AS carrier, l.accrued_cents, l.invoiced_at, l.currency
    FROM shipment_ledger l
    JOIN shipments s ON s.id = l.shipment_id
    JOIN carriers c ON c.id = s.carrier_id
    WHERE ${conditions.join(" AND ")}
    ORDER BY ${orderBy} DESC NULLS LAST
    LIMIT $${args.length}
  `;

  try {
    const rows = await withClient(async (client) => {
      const result = await client.queryObject<LedgerRow>(sql, args);
      return result.rows;
    });
    const accrued = rows.reduce((total, row) => total + row.accrued_cents, 0);
    log.info("shipment ledger", { requestId: ctx.requestId, org: ctx.session.orgId, hits: rows.length });
    return json({ entries: rows, count: rows.length, accruedCents: accrued });
  } catch (error) {
    log.error("shipment ledger failed", { requestId: ctx.requestId, org: ctx.session.orgId, error: String(error) });
    return problem(500, "The ledger is temporarily unavailable. Try again in a moment.");
  }
}
