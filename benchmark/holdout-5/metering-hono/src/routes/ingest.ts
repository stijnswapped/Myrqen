import { Hono } from 'hono';
import type { AppEnv } from '../bindings';
import { currentPeriod, isKnownMetric } from '../bindings';
import { requireApiKey, requireScope } from '../middleware/apiKey';

const ingest = new Hono<AppEnv>();

/** Counters live for two periods so late events still land on a warm key. */
const COUNTER_TTL_SECONDS = 60 * 60 * 24 * 70;
const MAX_QUANTITY = 1_000_000;

interface UsageBody {
  customerId?: string;
  metric?: string;
  quantity?: number;
  occurredAt?: string;
  idempotencyKey?: string;
}

function counterKey(accountId: string, customerId: string, metric: string, period: string): string {
  return `usage:${accountId}:${customerId}:${metric}:${period}`;
}

/**
 * Record one usage event and enforce the customer's quota for the current period.
 *
 * The hot path deliberately avoids a D1 read: the running total lives in KV, which
 * the reconciliation job folds back into `quotas` every night.
 */
ingest.post('/v1/usage', async (c) => {
  const key = requireApiKey(c);
  requireScope(key, 'usage:write');

  const body = await c.req.json<UsageBody>();
  if (!body.customerId || !isKnownMetric(body.metric)) {
    return c.json({ error: 'customerId and a known metric are required' }, 400);
  }
  const quantity = Number(body.quantity ?? 1);
  if (!Number.isFinite(quantity) || quantity <= 0 || quantity > MAX_QUANTITY) {
    return c.json({ error: 'quantity must be a positive number' }, 400);
  }

  const customer = await c.env.DB.prepare(
    `SELECT id FROM customers WHERE id = ?1 AND account_id = ?2`,
  )
    .bind(body.customerId, key.accountId)
    .first<{ id: string }>();
  if (!customer) {
    return c.json({ error: 'customer not found' }, 404);
  }

  const period = currentPeriod();
  const cacheKey = counterKey(key.accountId, customer.id, body.metric, period);

  const quota = await c.env.DB.prepare(
    `SELECT limit_units
       FROM quotas
      WHERE account_id = ?1
        AND customer_id = ?2
        AND metric = ?3
        AND period = ?4`,
  )
    .bind(key.accountId, customer.id, body.metric, period)
    .first<{ limit_units: number }>();

  // Read the running total, decide, then write it back. KV round trips inside a
  // single colo are a couple of milliseconds, so the window between the read and the
  // write is far too small for a customer to slip a second event through it.
  const used = Number((await c.env.COUNTERS.get(cacheKey)) ?? '0');
  if (quota && used + quantity > quota.limit_units) {
    return c.json(
      { error: 'quota_exceeded', metric: body.metric, limit: quota.limit_units, used },
      429,
    );
  }
  await c.env.COUNTERS.put(cacheKey, String(used + quantity), {
    expirationTtl: COUNTER_TTL_SECONDS,
  });

  const occurredAt = body.occurredAt ?? new Date().toISOString();
  const eventId = crypto.randomUUID();
  try {
    await c.env.DB.prepare(
      `INSERT INTO usage_events (id, account_id, customer_id, metric, quantity, occurred_at, idempotency_key, source)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'api')`,
    )
      .bind(
        eventId,
        key.accountId,
        customer.id,
        body.metric,
        quantity,
        occurredAt,
        body.idempotencyKey ?? null,
      )
      .run();
  } catch (error) {
    if (String(error).includes('UNIQUE')) {
      return c.json({ accepted: true, duplicate: true }, 200);
    }
    throw error;
  }

  return c.json(
    {
      accepted: true,
      eventId,
      metric: body.metric,
      used: used + quantity,
      limit: quota?.limit_units ?? null,
    },
    202,
  );
});

/** Batch variant used by the SDK's buffered client. Same rules, one round trip. */
ingest.post('/v1/usage/batch', async (c) => {
  const key = requireApiKey(c);
  requireScope(key, 'usage:write');

  const body = await c.req.json<{ events?: UsageBody[] }>();
  const events = body.events ?? [];
  if (events.length === 0 || events.length > 500) {
    return c.json({ error: 'send between 1 and 500 events' }, 400);
  }

  const period = currentPeriod();
  const accepted: string[] = [];
  const statements = [];

  for (const event of events) {
    if (!event.customerId || !isKnownMetric(event.metric)) {
      return c.json({ error: 'every event needs customerId and a known metric' }, 400);
    }
    const quantity = Number(event.quantity ?? 1);
    if (!Number.isFinite(quantity) || quantity <= 0) {
      return c.json({ error: 'quantity must be a positive number' }, 400);
    }
    const eventId = crypto.randomUUID();
    accepted.push(eventId);
    statements.push(
      c.env.DB.prepare(
        `INSERT INTO usage_events (id, account_id, customer_id, metric, quantity, occurred_at, idempotency_key, source)
         SELECT ?1, ?2, id, ?3, ?4, ?5, ?6, 'sdk' FROM customers WHERE id = ?7 AND account_id = ?2`,
      ).bind(
        eventId,
        key.accountId,
        event.metric,
        quantity,
        event.occurredAt ?? new Date().toISOString(),
        event.idempotencyKey ?? null,
        event.customerId,
      ),
    );
  }

  await c.env.DB.batch(statements);
  return c.json({ accepted: accepted.length, period, eventIds: accepted }, 202);
});

export default ingest;
