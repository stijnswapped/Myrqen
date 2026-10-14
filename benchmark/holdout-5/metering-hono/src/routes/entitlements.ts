import { Hono } from 'hono';
import type { AppEnv } from '../bindings';
import { PERIOD_PATTERN, currentPeriod } from '../bindings';
import { requireApiKey, requireScope } from '../middleware/apiKey';

const entitlements = new Hono<AppEnv>();

interface EntitlementRow {
  metric: string;
  limit_units: number;
  used_units: number;
  period: string;
}

/**
 * Plan entitlements plus current consumption for one customer.
 *
 * Same lookup shape as /v1/quota/:customerId, but the account id from the resolved
 * key is part of the WHERE clause, so a customer id belonging to another tenant
 * simply produces no rows and a 404. There is no separate ownership query to keep
 * in sync with this one.
 */
entitlements.get('/v1/entitlements/:customerId', async (c) => {
  const key = requireApiKey(c);
  requireScope(key, 'quota:read');

  const customerId = c.req.param('customerId');
  const period = c.req.query('period') ?? currentPeriod();
  if (!PERIOD_PATTERN.test(period)) {
    return c.json({ error: 'period must be YYYY-MM' }, 400);
  }

  const result = await c.env.DB.prepare(
    `SELECT metric, limit_units, used_units, period
       FROM quotas
      WHERE account_id = ?1
        AND customer_id = ?2
        AND period = ?3
   ORDER BY metric ASC`,
  )
    .bind(key.accountId, customerId, period)
    .all<EntitlementRow>();

  const rows = result.results ?? [];
  if (rows.length === 0) {
    return c.json({ error: 'customer has no entitlements for this period' }, 404);
  }

  return c.json({
    customerId,
    period,
    entitlements: rows.map((row) => ({
      metric: row.metric,
      limit: row.limit_units,
      used: row.used_units,
      remaining: Math.max(row.limit_units - row.used_units, 0),
    })),
  });
});

/**
 * Raise or lower a customer's limit. The UPDATE carries the account id too, so a
 * mis-typed customer id changes nothing rather than changing somebody else's plan.
 */
entitlements.patch('/v1/entitlements/:customerId', async (c) => {
  const key = requireApiKey(c);
  requireScope(key, 'quota:write');

  const customerId = c.req.param('customerId');
  const body = await c.req.json<{ metric?: string; limit?: number }>();
  if (!body.metric || typeof body.limit !== 'number' || body.limit < 0) {
    return c.json({ error: 'metric and a non-negative limit are required' }, 400);
  }

  const period = currentPeriod();
  const updated = await c.env.DB.prepare(
    `UPDATE quotas
        SET limit_units = ?1,
            updated_at = ?2
      WHERE account_id = ?3
        AND customer_id = ?4
        AND metric = ?5
        AND period = ?6`,
  )
    .bind(body.limit, new Date().toISOString(), key.accountId, customerId, body.metric, period)
    .run();

  if (updated.meta.changes === 0) {
    return c.json({ error: 'no matching entitlement' }, 404);
  }

  return c.json({ customerId, metric: body.metric, limit: body.limit, period });
});

export default entitlements;
