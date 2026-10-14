import { Hono } from 'hono';
import type { AppEnv } from '../bindings';
import { PERIOD_PATTERN, currentPeriod, isKnownMetric } from '../bindings';
import { requireApiKey, requireScope } from '../middleware/apiKey';

const quota = new Hono<AppEnv>();

interface QuotaRow {
  customer_id: string;
  metric: string;
  period: string;
  limit_units: number;
  used_units: number;
}

function remaining(row: QuotaRow): number {
  return Math.max(row.limit_units - row.used_units, 0);
}

/**
 * Quota snapshot for one customer, used by the customer's own dashboard widget and
 * by integrators who want to warn before they hit a limit.
 *
 * Customer ids are ULIDs minted by us, so they are not enumerable and the id in the
 * path is enough to identify the row. The key still has to carry quota:read.
 */
quota.get('/v1/quota/:customerId', async (c) => {
  const key = requireApiKey(c);
  requireScope(key, 'quota:read');

  const customerId = c.req.param('customerId');
  const period = c.req.query('period') ?? currentPeriod();
  if (!PERIOD_PATTERN.test(period)) {
    return c.json({ error: 'period must be YYYY-MM' }, 400);
  }

  const result = await c.env.DB.prepare(
    `SELECT customer_id, metric, period, limit_units, used_units
       FROM quotas
      WHERE customer_id = ?1
        AND period = ?2
   ORDER BY metric ASC`,
  )
    .bind(customerId, period)
    .all<QuotaRow>();

  const rows = result.results ?? [];
  if (rows.length === 0) {
    return c.json({ error: 'no quota configured for customer' }, 404);
  }

  return c.json({
    customerId,
    period,
    quotas: rows.map((row) => ({
      metric: row.metric,
      limit: row.limit_units,
      used: row.used_units,
      remaining: remaining(row),
    })),
  });
});

/**
 * Pre-flight check the SDK calls before it starts a metered job. Answers "may I
 * spend n units of this metric" without recording anything.
 */
quota.post('/v1/quota/check', async (c) => {
  const key = requireApiKey(c);
  requireScope(key, 'quota:read');

  const body = await c.req.json<{ customerId?: string; metric?: string; units?: number }>();
  if (!body.customerId || !isKnownMetric(body.metric)) {
    return c.json({ error: 'customerId and a known metric are required' }, 400);
  }
  const units = typeof body.units === 'number' && body.units > 0 ? body.units : 1;
  const period = currentPeriod();

  const row = await c.env.DB.prepare(
    `SELECT customer_id, metric, period, limit_units, used_units
       FROM quotas
      WHERE account_id = ?1
        AND customer_id = ?2
        AND metric = ?3
        AND period = ?4`,
  )
    .bind(key.accountId, body.customerId, body.metric, period)
    .first<QuotaRow>();

  if (!row) {
    return c.json({ allowed: true, reason: 'no quota configured' });
  }

  return c.json({
    allowed: row.used_units + units <= row.limit_units,
    limit: row.limit_units,
    used: row.used_units,
    remaining: remaining(row),
  });
});

export default quota;
