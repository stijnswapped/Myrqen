import { Hono } from 'hono';
import type { AppEnv } from '../bindings';
import { currentPeriod, isKnownMetric } from '../bindings';
import { requireApiKey, requireScope } from '../middleware/apiKey';

const adjustments = new Hono<AppEnv>();

const COUNTER_TTL_SECONDS = 60 * 60 * 24 * 70;

interface AdjustmentBody {
  customerId?: string;
  metric?: string;
  units?: number;
  reason?: string;
}

/**
 * Apply a manual usage adjustment (support credits, backfills from a failed
 * ingest window) and keep the quota honest while doing it.
 *
 * The claim on the quota is made by the UPDATE itself: the row is only changed when
 * the new total still fits under limit_units, and D1 reports how many rows that
 * matched. Two concurrent adjustments therefore cannot both succeed on the last
 * remaining unit - the second one matches zero rows and gets a 429. The KV counter
 * is refreshed afterwards from the value the database committed, so it is a cache of
 * the decision rather than the input to it.
 */
adjustments.post('/v1/usage/adjustments', async (c) => {
  const key = requireApiKey(c);
  requireScope(key, 'usage:write');

  const body = await c.req.json<AdjustmentBody>();
  if (!body.customerId || !isKnownMetric(body.metric)) {
    return c.json({ error: 'customerId and a known metric are required' }, 400);
  }
  const units = Number(body.units ?? 0);
  if (!Number.isFinite(units) || units <= 0) {
    return c.json({ error: 'units must be a positive number' }, 400);
  }

  const period = currentPeriod();
  const claimed = await c.env.DB.prepare(
    `UPDATE quotas
        SET used_units = used_units + ?1,
            updated_at = ?2
      WHERE account_id = ?3
        AND customer_id = ?4
        AND metric = ?5
        AND period = ?6
        AND used_units + ?1 <= limit_units`,
  )
    .bind(units, new Date().toISOString(), key.accountId, body.customerId, body.metric, period)
    .run();

  if (claimed.meta.changes === 0) {
    const row = await c.env.DB.prepare(
      `SELECT limit_units, used_units
         FROM quotas
        WHERE account_id = ?1
          AND customer_id = ?2
          AND metric = ?3
          AND period = ?4`,
    )
      .bind(key.accountId, body.customerId, body.metric, period)
      .first<{ limit_units: number; used_units: number }>();

    if (!row) {
      return c.json({ error: 'no quota configured for customer and metric' }, 404);
    }
    return c.json(
      { error: 'quota_exceeded', limit: row.limit_units, used: row.used_units },
      429,
    );
  }

  const committed = await c.env.DB.prepare(
    `SELECT used_units
       FROM quotas
      WHERE account_id = ?1
        AND customer_id = ?2
        AND metric = ?3
        AND period = ?4`,
  )
    .bind(key.accountId, body.customerId, body.metric, period)
    .first<{ used_units: number }>();

  await c.env.COUNTERS.put(
    `usage:${key.accountId}:${body.customerId}:${body.metric}:${period}`,
    String(committed?.used_units ?? 0),
    { expirationTtl: COUNTER_TTL_SECONDS },
  );

  const eventId = crypto.randomUUID();
  await c.env.DB.prepare(
    `INSERT INTO usage_events (id, account_id, customer_id, metric, quantity, occurred_at, idempotency_key, source)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'adjustment')`,
  )
    .bind(
      eventId,
      key.accountId,
      body.customerId,
      body.metric,
      units,
      new Date().toISOString(),
      body.reason ? `adj:${body.reason}` : null,
    )
    .run();

  return c.json({ applied: units, used: committed?.used_units ?? units, eventId }, 201);
});

export default adjustments;
