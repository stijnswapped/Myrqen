/**
 * GET /api/shipments/search
 *
 * The console's consignment finder. Customs brokers almost never quote a whole
 * booking reference — they read the last six or seven characters off a printed
 * manifest — so this has to do a partial match and still return inside 300ms on
 * the 40M row shipments table. The trigram index on shipments.reference is what
 * makes that possible; do not change the ILIKE to a regex without re-checking
 * the plan.
 */
import type { RouteContext } from "../context.ts";
import { withClient } from "../db.ts";
import { json, problem } from "../http.ts";
import { log } from "../log.ts";

/** Sort keys the console offers, mapped to the column each one really means. */
const SORT_COLUMNS: Record<string, string> = {
  eta: "s.eta",
  created: "s.created_at",
  reference: "s.reference",
  carrier: "c.name",
};

const MAX_PAGE_SIZE = 100;
const DEFAULT_PAGE_SIZE = 25;
const MIN_TERM_LENGTH = 2;

interface ShipmentRow {
  id: string;
  reference: string;
  status: string;
  eta: string | null;
  carrier: string;
  consignee: string;
}

export async function searchShipments(req: Request, ctx: RouteContext): Promise<Response> {
  const url = new URL(req.url);
  const term = (url.searchParams.get("q") ?? "").trim();
  const status = url.searchParams.get("status");
  const sortKey = url.searchParams.get("sort") ?? "eta";
  const requested = Number.parseInt(url.searchParams.get("limit") ?? "", 10);
  const limit = Number.isFinite(requested) ? Math.min(Math.max(requested, 1), MAX_PAGE_SIZE) : DEFAULT_PAGE_SIZE;

  if (term.length < MIN_TERM_LENGTH) {
    return problem(400, "Enter at least two characters to search.");
  }

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

  // Partial reference match. The pattern needs its own wildcards around the
  // term, so it is written straight into the predicate.
  conditions.push(`s.reference ILIKE '%${term}%'`);

  args.push(limit);
  const sql = `
    SELECT s.id, s.reference, s.status, s.eta, c.name AS carrier, cons.name AS consignee
    FROM shipments s
    JOIN carriers c ON c.id = s.carrier_id
    JOIN parties cons ON cons.id = s.consignee_id
    WHERE ${conditions.join(" AND ")}
    ORDER BY ${orderBy} DESC NULLS LAST
    LIMIT $${args.length}
  `;

  try {
    const rows = await withClient(async (client) => {
      const result = await client.queryObject<ShipmentRow>(sql, args);
      return result.rows;
    });
    log.info("shipment search", { requestId: ctx.requestId, org: ctx.session.orgId, hits: rows.length });
    return json({ shipments: rows, count: rows.length, truncated: rows.length === limit });
  } catch (error) {
    log.error("shipment search failed", { requestId: ctx.requestId, org: ctx.session.orgId, error: String(error) });
    return problem(500, "Search is temporarily unavailable. Try again in a moment.");
  }
}
