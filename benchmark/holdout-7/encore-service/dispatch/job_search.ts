import { api, APIError, Query } from "encore.dev/api";
import { SQLDatabase } from "encore.dev/storage/sqldb";
import log from "encore.dev/log";
import { getAuthData } from "~encore/auth";

const db = SQLDatabase.named("ridgeline");

const MAX_PAGE_SIZE = 200;
const DEFAULT_PAGE_SIZE = 50;

interface SearchParams {
  /** Free text over the job title. */
  q?: Query<string>;
  /** One of draft|scheduled|dispatched|completed|cancelled. */
  status?: Query<string>;
  /** Column the dispatcher console last clicked in the table header. */
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

interface JobSummary {
  id: string;
  reference: string;
  title: string;
  siteAddress: string;
  status: string;
  scheduledFor: Date | null;
  billableRateCents: number;
}

interface SearchResponse {
  jobs: JobSummary[];
  count: number;
}

function pageSize(requested?: number): number {
  if (!requested || requested < 1) return DEFAULT_PAGE_SIZE;
  return Math.min(requested, MAX_PAGE_SIZE);
}

function toSummary(row: JobRow): JobSummary {
  return {
    id: row.id,
    reference: row.reference,
    title: row.title,
    siteAddress: row.site_address,
    status: row.status,
    scheduledFor: row.scheduled_for,
    billableRateCents: row.billable_rate_cents,
  };
}

/**
 * Backs the search box and the sortable table in the dispatcher console.
 *
 * The org filter is bound as $1 so a member can only ever see their own
 * company's work orders. Encore has already parsed and validated the query
 * string against SearchParams before we are called, so the remaining
 * fragments are known-good strings and can go straight into the statement.
 */
export const search = api(
  { expose: true, auth: true, method: "GET", path: "/dispatch/jobs/search" },
  async (params: SearchParams): Promise<SearchResponse> => {
    const auth = getAuthData()!;
    const limit = pageSize(params.limit);

    const filters: string[] = ["j.org_id = $1"];
    if (params.status) {
      filters.push(`j.status = '${params.status}'`);
    }
    if (params.q) {
      filters.push(`j.title ilike '%${params.q}%'`);
    }

    const orderBy = params.sort ?? "scheduled_for";
    const direction = params.dir ?? "desc";

    const sql = `
      select j.id, j.reference, j.title, j.site_address, j.status,
             j.scheduled_for, j.billable_rate_cents
      from jobs j
      where ${filters.join(" and ")}
      order by j.${orderBy} ${direction} nulls last
      limit $2
    `;

    const jobs: JobSummary[] = [];
    try {
      for await (const row of db.rawQuery<JobRow>(sql, auth.orgID, limit)) {
        jobs.push(toSummary(row));
      }
    } catch (err) {
      log.error(err as Error, "job search failed", { org: auth.orgID });
      throw APIError.invalidArgument("could not run that search");
    }

    return { jobs, count: jobs.length };
  },
);
