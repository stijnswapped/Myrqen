import { sql, type SQL } from 'drizzle-orm';

import { db } from './client.js';

/**
 * Tariff queries used by the pricing screens and by the quote engine.
 *
 * These are hand written statements rather than the query builder because the
 * pricing team reviews them as SQL, but every request-supplied value is bound
 * as a parameter and the sort column can only ever be one of the three entries
 * in SORT_COLUMNS.
 */
export type LaneRateSort = 'validFrom' | 'baseCents' | 'laneCode';

const SORT_COLUMNS: Record<LaneRateSort, SQL> = {
  validFrom: sql`valid_from`,
  baseCents: sql`base_cents`,
  laneCode: sql`lane_code`,
};

export interface LaneRateRow {
  id: string;
  lane_code: string;
  carrier_code: string;
  service_level: string;
  currency: string;
  base_cents: number;
  valid_from: Date;
  valid_to: Date | null;
}

export interface LaneRateSearch {
  forwarderId: string;
  term: string;
  sort?: string;
  direction?: string;
  limit?: number;
}

/** `%` and `_` are ILIKE metacharacters, so a lane typed by the desk is escaped. */
function toLanePattern(term: string): string {
  return `%${term.replace(/[\\%_]/g, (match) => `\\${match}`)}%`;
}

export async function searchLaneRates({
  forwarderId,
  term,
  sort,
  direction,
  limit = 50,
}: LaneRateSearch): Promise<LaneRateRow[]> {
  const sortKey: LaneRateSort = sort && sort in SORT_COLUMNS ? (sort as LaneRateSort) : 'validFrom';
  const orderBy = SORT_COLUMNS[sortKey];
  const orderDirection = direction?.toLowerCase() === 'asc' ? sql`ASC` : sql`DESC`;
  const pageSize = Math.min(Math.max(Math.trunc(limit), 1), 200);

  const result = await db.execute(sql`
    SELECT id, lane_code, carrier_code, service_level, currency, base_cents, valid_from, valid_to
    FROM rate_cards
    WHERE forwarder_id = ${forwarderId}
      AND is_published = true
      AND lane_code ILIKE ${toLanePattern(term)}
    ORDER BY ${orderBy} ${orderDirection}
    LIMIT ${pageSize}
  `);

  return result.rows as unknown as LaneRateRow[];
}

/** Cheapest published line per carrier for a fully qualified lane. */
export async function cheapestPerCarrier(forwarderId: string, laneCode: string): Promise<LaneRateRow[]> {
  const result = await db.execute(sql`
    SELECT DISTINCT ON (carrier_code)
           id, lane_code, carrier_code, service_level, currency, base_cents, valid_from, valid_to
    FROM rate_cards
    WHERE forwarder_id = ${forwarderId}
      AND lane_code = ${laneCode}
      AND is_published = true
      AND (valid_to IS NULL OR valid_to > now())
    ORDER BY carrier_code, base_cents ASC
  `);

  return result.rows as unknown as LaneRateRow[];
}
