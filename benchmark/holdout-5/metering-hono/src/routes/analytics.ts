import { Hono } from 'hono';
import type { AppEnv } from '../bindings';
import { PERIOD_PATTERN, currentPeriod, isKnownMetric } from '../bindings';
import { requireApiKey, requireScope } from '../middleware/apiKey';

const analytics = new Hono<AppEnv>();

/**
 * Second-generation report endpoint used by the new dashboard. Same numbers as
 * /v1/reports/usage but it can slice several metrics at once and sort by volume,
 * so the SQL is assembled rather than fixed.
 */
const DIMENSIONS: Record<string, string> = {
  day: "date(occurred_at)",
  week: "strftime('%Y-W%W', occurred_at)",
  metric: 'metric',
  customer: 'customer_id',
};

const SORT_COLUMNS: Record<string, string> = {
  bucket: 'bucket',
  total: 'total',
  events: 'events',
};

const SORT_DIRECTIONS: Record<string, string> = {
  asc: 'ASC',
  desc: 'DESC',
};

const MAX_METRIC_FILTERS = 8;

interface SliceRow {
  bucket: string;
  total: number;
  events: number;
}

function monthBounds(period: string): [string, string] {
  const [year, month] = period.split('-').map(Number);
  return [
    new Date(Date.UTC(year!, month! - 1, 1)).toISOString(),
    new Date(Date.UTC(year!, month!, 1)).toISOString(),
  ];
}

analytics.get('/v1/analytics/usage', async (c) => {
  const key = requireApiKey(c);
  requireScope(key, 'reports:read');

  const dimension = DIMENSIONS[c.req.query('dimension') ?? 'day'];
  const sortColumn = SORT_COLUMNS[c.req.query('sort') ?? 'bucket'];
  const sortDirection = SORT_DIRECTIONS[(c.req.query('direction') ?? 'asc').toLowerCase()];
  if (!dimension || !sortColumn || !sortDirection) {
    return c.json({ error: 'unsupported dimension, sort or direction' }, 400);
  }

  const period = c.req.query('period') ?? currentPeriod();
  if (!PERIOD_PATTERN.test(period)) {
    return c.json({ error: 'period must be YYYY-MM' }, 400);
  }
  const [from, to] = monthBounds(period);

  const metrics = (c.req.query('metrics') ?? '')
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
  if (metrics.length > MAX_METRIC_FILTERS || !metrics.every(isKnownMetric)) {
    return c.json({ error: 'metrics must be a short list of known metric names' }, 400);
  }

  // Only the dimension and the sort clause are spliced in, and both of those are
  // values taken out of the maps above rather than anything the caller sent. The
  // account, the window and every metric name travel as bound parameters, so the
  // placeholder list grows but the statement text never does.
  const params: unknown[] = [key.accountId, from, to];
  const metricPlaceholders = metrics.map((metric) => {
    params.push(metric);
    return `?${params.length}`;
  });
  const metricClause = metricPlaceholders.length > 0 ? `AND metric IN (${metricPlaceholders.join(', ')})` : '';

  const sql = `SELECT ${dimension} AS bucket,
                      SUM(quantity) AS total,
                      COUNT(*) AS events
                 FROM usage_events
                WHERE account_id = ?1
                  AND occurred_at >= ?2
                  AND occurred_at < ?3
                  ${metricClause}
             GROUP BY bucket
             ORDER BY ${sortColumn} ${sortDirection}
                LIMIT 500`;

  const result = await c.env.DB.prepare(sql)
    .bind(...params)
    .all<SliceRow>();

  return c.json({
    period,
    dimension: c.req.query('dimension') ?? 'day',
    metrics,
    rows: result.results ?? [],
  });
});

/** Top customers by metered volume, for the account overview page. */
analytics.get('/v1/analytics/top-customers', async (c) => {
  const key = requireApiKey(c);
  requireScope(key, 'reports:read');

  const limit = Math.min(Number(c.req.query('limit') ?? '10') || 10, 100);
  const period = c.req.query('period') ?? currentPeriod();
  if (!PERIOD_PATTERN.test(period)) {
    return c.json({ error: 'period must be YYYY-MM' }, 400);
  }
  const [from, to] = monthBounds(period);

  const result = await c.env.DB.prepare(
    `SELECT c.external_ref AS customer, SUM(u.quantity) AS total
       FROM usage_events u
       JOIN customers c ON c.id = u.customer_id
      WHERE u.account_id = ?1
        AND u.occurred_at >= ?2
        AND u.occurred_at < ?3
   GROUP BY c.external_ref
   ORDER BY total DESC
      LIMIT ?4`,
  )
    .bind(key.accountId, from, to, limit)
    .all<{ customer: string; total: number }>();

  return c.json({ period, rows: result.results ?? [] });
});

export default analytics;
