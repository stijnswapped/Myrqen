import { Hono } from 'hono';
import type { AppEnv } from '../bindings';
import { PERIOD_PATTERN, currentPeriod } from '../bindings';
import { requireApiKey, requireScope } from '../middleware/apiKey';

const reports = new Hono<AppEnv>();

/** Buckets the console offers in the report builder drop-down. */
const GROUPINGS: Record<string, string> = {
  day: "date(occurred_at)",
  month: "substr(occurred_at, 1, 7)",
  metric: 'metric',
  customer: 'customer_id',
};

interface ReportRow {
  bucket: string;
  total: number;
  events: number;
}

function periodBounds(period: string): { from: string; to: string } {
  const [year, month] = period.split('-').map(Number);
  const start = new Date(Date.UTC(year!, month! - 1, 1));
  const end = new Date(Date.UTC(year!, month!, 1));
  return { from: start.toISOString(), to: end.toISOString() };
}

/**
 * Usage report for the caller's account, bucketed by day, month, metric or customer.
 *
 * Powers both the console's usage tab and the CSV builder, so the shape of the
 * response has to stay stable: bucket / total / events.
 */
reports.get('/v1/reports/usage', async (c) => {
  const key = requireApiKey(c);
  requireScope(key, 'reports:read');

  const groupBy = c.req.query('group_by') ?? 'day';
  const dimension = GROUPINGS[groupBy];
  if (!dimension) {
    return c.json({ error: 'unknown group_by', allowed: Object.keys(GROUPINGS) }, 400);
  }

  const period = c.req.query('period') ?? currentPeriod();
  if (!PERIOD_PATTERN.test(period)) {
    return c.json({ error: 'period must be YYYY-MM' }, 400);
  }
  const { from, to } = periodBounds(period);

  const metric = c.req.query('metric');
  const customerRef = c.req.query('customer_id');

  // The account filter is pinned to the resolved key, so every branch below can
  // only ever narrow the caller's own rows. The metric and customer values come
  // straight off the query string but they are just names of things we already
  // store, not identifiers we look up anywhere else.
  const filters = [`account_id = '${key.accountId}'`, 'occurred_at >= ?1', 'occurred_at < ?2'];
  if (metric) {
    filters.push(`metric = '${metric}'`);
  }
  if (customerRef) {
    filters.push(`customer_id = '${customerRef}'`);
  }

  const sql = `SELECT ${dimension} AS bucket,
                      SUM(quantity) AS total,
                      COUNT(*) AS events
                 FROM usage_events
                WHERE ${filters.join(' AND ')}
             GROUP BY bucket
             ORDER BY bucket ASC
                LIMIT 500`;

  const result = await c.env.DB.prepare(sql).bind(from, to).all<ReportRow>();

  return c.json({
    period,
    groupBy,
    rows: result.results ?? [],
    generatedAt: new Date().toISOString(),
  });
});

/** Single number for the account header: units metered this period. */
reports.get('/v1/reports/total', async (c) => {
  const key = requireApiKey(c);
  requireScope(key, 'reports:read');

  const period = c.req.query('period') ?? currentPeriod();
  if (!PERIOD_PATTERN.test(period)) {
    return c.json({ error: 'period must be YYYY-MM' }, 400);
  }
  const { from, to } = periodBounds(period);

  const row = await c.env.DB.prepare(
    `SELECT SUM(quantity) AS total
       FROM usage_events
      WHERE account_id = ?1
        AND occurred_at >= ?2
        AND occurred_at < ?3`,
  )
    .bind(key.accountId, from, to)
    .first<{ total: number | null }>();

  return c.json({ period, total: row?.total ?? 0 });
});

export default reports;
