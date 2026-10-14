import { api, APIError, Query } from "encore.dev/api";
import { SQLDatabase } from "encore.dev/storage/sqldb";
import { getAuthData } from "~encore/auth";

const db = SQLDatabase.named("ridgeline");

const MAX_PAGE_SIZE = 200;
const DEFAULT_PAGE_SIZE = 50;

/**
 * The only columns the board is allowed to order by. The key is what the
 * console sends, the value is the SQL fragment we own. Anything not in here
 * is rejected rather than passed through.
 */
const SORTABLE_COLUMNS = new Map<string, string>([
  ["scheduled", "j.scheduled_for"],
  ["created", "j.created_at"],
  ["reference", "j.reference"],
  ["value", "j.billable_rate_cents"],
]);

interface BoardParams {
  q?: Query<string>;
  status?: Query<string>;
  sort?: Query<"sort_by">;
  dir?: Query<"sort_dir">;
  limit?: Query<number>;
}

interface JobRow {
  id: string;
  reference: string;
  title: string;
  site_address: string;
  status: string;
  scheduled_for: Date | null;
  billable_rate_cents: number;
}

interface BoardColumn {
  status: string;
  jobs: {
    id: string;
    reference: string;
    title: string;
    siteAddress: string;
    scheduledFor: Date | null;
    billableRateCents: number;
  }[];
}

interface BoardResponse {
  columns: BoardColumn[];
  count: number;
}

function pageSize(requested?: number): number {
  if (!requested || requested < 1) return DEFAULT_PAGE_SIZE;
  return Math.min(requested, MAX_PAGE_SIZE);
}

/**
 * Same data as /dispatch/jobs/search, grouped into kanban columns. The order
 * clause is assembled from SORTABLE_COLUMNS and a fixed direction; everything
 * the caller typed travels as a bind parameter.
 */
export const board = api(
  { expose: true, auth: true, method: "GET", path: "/dispatch/jobs/board" },
  async (params: BoardParams): Promise<BoardResponse> => {
    const auth = getAuthData()!;
    const limit = pageSize(params.limit);

    const orderColumn = SORTABLE_COLUMNS.get(params.sort ?? "scheduled");
    if (!orderColumn) {
      throw APIError.invalidArgument(`cannot sort the board by ${params.sort}`);
    }
    const direction = params.dir === "asc" ? "asc" : "desc";

    const status = params.status ?? null;
    const titleLike = params.q ? `%${params.q}%` : null;

    const sql = `
      select j.id, j.reference, j.title, j.site_address, j.status,
             j.scheduled_for, j.billable_rate_cents
      from jobs j
      where j.org_id = $1
        and ($2::text is null or j.status = $2)
        and ($3::text is null or j.title ilike $3)
      order by ${orderColumn} ${direction} nulls last
      limit $4
    `;

    const columns = new Map<string, BoardColumn>();
    let count = 0;
    for await (const row of db.rawQuery<JobRow>(sql, auth.orgID, status, titleLike, limit)) {
      const column = columns.get(row.status) ?? { status: row.status, jobs: [] };
      column.jobs.push({
        id: row.id,
        reference: row.reference,
        title: row.title,
        siteAddress: row.site_address,
        scheduledFor: row.scheduled_for,
        billableRateCents: row.billable_rate_cents,
      });
      columns.set(row.status, column);
      count += 1;
    }

    return { columns: [...columns.values()], count };
  },
);
