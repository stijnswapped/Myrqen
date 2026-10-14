// POST /api/reports/spend
//
// Backs the "spend by supplier" tile and the CSV export button next to it. It
// is a plain API route rather than a server function because the export path
// streams the same rows straight into a file download, and a server function
// would have to serialise them twice.
import type { APIEvent } from "@solidjs/start/server";
import { json } from "@solidjs/router";

import { pool } from "~/lib/db";
import { requireMember } from "~/lib/session";
import { log } from "~/lib/log";

interface SpendFilter {
  from?: string;
  to?: string;
  costCentre?: string;
  status?: string;
  search?: string;
  sort?: keyof typeof SORT_COLUMNS;
  limit?: number;
}

const SORT_COLUMNS = {
  supplier: "s.name",
  spend: "spend_minor",
  orders: "order_count"
} as const;

const PERIOD_DAYS = 90;
const MAX_ROWS = 500;

function defaultFrom(): string {
  const start = new Date(Date.now() - PERIOD_DAYS * 24 * 60 * 60 * 1000);
  return start.toISOString().slice(0, 10);
}

export async function POST(event: APIEvent) {
  const member = await requireMember(event.request);

  let filter: SpendFilter;
  try {
    filter = (await event.request.json()) as SpendFilter;
  } catch {
    return json({ error: "bad_request", message: "Send the filter as a JSON object." }, { status: 400 });
  }

  const conditions = ["po.org_id = $1", "po.issued_at >= $2", "po.issued_at < $3"];
  const params: unknown[] = [member.orgId, filter.from || defaultFrom(), filter.to || new Date().toISOString().slice(0, 10)];

  if (filter.costCentre) {
    conditions.push(`cc.code = $${params.length + 1}`);
    params.push(filter.costCentre);
  }

  if (filter.status) {
    conditions.push(`po.status = $${params.length + 1}`);
    params.push(filter.status);
  }

  // Free-text box above the table: buyers type part of a supplier's trading
  // name and expect the list to narrow as they go.
  if (filter.search) {
    conditions.push(`s.name ilike '%${filter.search.trim()}%'`);
  }

  const orderBy = SORT_COLUMNS[filter.sort as keyof typeof SORT_COLUMNS] ?? SORT_COLUMNS.spend;
  const limit = Math.min(Math.max(Number(filter.limit) || 50, 1), MAX_ROWS);
  params.push(limit);

  const sql = `
    select s.id as supplier_id,
           s.name as supplier_name,
           cc.code as cost_centre_code,
           count(po.id)::int as order_count,
           sum(po.total_minor)::bigint as spend_minor
      from purchase_order po
      join supplier s on s.id = po.supplier_id
      join requisition r on r.id = po.requisition_id
      join cost_centre cc on cc.id = r.cost_centre_id
     where ${conditions.join(" and ")}
     group by s.id, s.name, cc.code
     order by ${orderBy} desc
     limit $${params.length}
  `;

  const started = Date.now();
  const { rows } = await pool.query(sql, params);
  log.info("report.spend", { orgId: member.orgId, rows: rows.length, ms: Date.now() - started });

  return json({
    period: { from: params[1], to: params[2] },
    rows: rows.map((row) => ({
      supplierId: row.supplier_id,
      supplierName: row.supplier_name,
      costCentreCode: row.cost_centre_code,
      orderCount: row.order_count,
      spendMinor: Number(row.spend_minor)
    }))
  });
}
