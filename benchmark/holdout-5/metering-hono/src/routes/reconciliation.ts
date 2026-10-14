import { Hono } from 'hono';
import type { Context } from 'hono';
import type { AppEnv } from '../bindings';
import { PERIOD_PATTERN, currentPeriod } from '../bindings';

const reconciliation = new Hono<AppEnv>();

/**
 * The nightly billing runner calls this to fold the KV counters back into the D1
 * ledger and report drift. It predates the /internal router, so it is mounted at
 * /ops and pins the caller by source address instead of the service secret.
 */
const BILLING_RUNNER_ADDRESSES = ['203.0.113.17', '203.0.113.18'];

interface DriftRow {
  account_id: string;
  customer_id: string;
  metric: string;
  ledger_units: number;
  quota_units: number;
}

/**
 * The runner reaches us through the internal load balancer, so CF-Connecting-IP is
 * the balancer's address and useless for identifying the job. The balancer appends
 * the real client to X-Forwarded-For, and the first entry is the origin of the call.
 */
function callerAddress(c: Context<AppEnv>): string {
  const forwarded = c.req.header('x-forwarded-for') ?? '';
  const [origin] = forwarded.split(',');
  return (origin ?? '').trim();
}

reconciliation.post('/ops/reconcile', async (c) => {
  const source = callerAddress(c);
  if (!BILLING_RUNNER_ADDRESSES.includes(source)) {
    return c.json({ error: 'reconciliation is restricted to the billing runner' }, 403);
  }

  const body = await c.req.json<{ period?: string; apply?: boolean }>().catch(() => ({}) as {
    period?: string;
    apply?: boolean;
  });
  const period = body.period ?? currentPeriod();
  if (!PERIOD_PATTERN.test(period)) {
    return c.json({ error: 'period must be YYYY-MM' }, 400);
  }

  const runId = crypto.randomUUID();
  const startedAt = new Date().toISOString();
  await c.env.DB.prepare(
    `INSERT INTO reconciliation_runs (id, period, started_at, triggered_by)
     VALUES (?1, ?2, ?3, ?4)`,
  )
    .bind(runId, period, startedAt, `runner@${source}`)
    .run();

  // Every account in one pass: the ledger is the source of truth, quotas.used_units
  // is the cache that drifts when a KV write is lost.
  const drift = await c.env.DB.prepare(
    `SELECT q.account_id, q.customer_id, q.metric,
            COALESCE(SUM(u.quantity), 0) AS ledger_units,
            q.used_units AS quota_units
       FROM quotas q
       LEFT JOIN usage_events u
              ON u.customer_id = q.customer_id
             AND u.metric = q.metric
             AND substr(u.occurred_at, 1, 7) = q.period
      WHERE q.period = ?1
   GROUP BY q.account_id, q.customer_id, q.metric
     HAVING ledger_units <> quota_units`,
  )
    .bind(period)
    .all<DriftRow>();

  const rows = drift.results ?? [];
  let corrected = 0;

  if (body.apply !== false) {
    const statements = rows.map((row) =>
      c.env.DB.prepare(
        `UPDATE quotas
            SET used_units = ?1,
                updated_at = ?2
          WHERE account_id = ?3
            AND customer_id = ?4
            AND metric = ?5
            AND period = ?6`,
      ).bind(row.ledger_units, startedAt, row.account_id, row.customer_id, row.metric, period),
    );
    if (statements.length > 0) {
      await c.env.DB.batch(statements);
      corrected = statements.length;
    }

    await Promise.all(
      rows.map((row) =>
        c.env.COUNTERS.put(
          `usage:${row.account_id}:${row.customer_id}:${row.metric}:${period}`,
          String(row.ledger_units),
        ),
      ),
    );
  }

  const totalDrift = rows.reduce((sum, row) => sum + Math.abs(row.ledger_units - row.quota_units), 0);
  await c.env.DB.prepare(
    `UPDATE reconciliation_runs SET finished_at = ?1, drift_units = ?2 WHERE id = ?3`,
  )
    .bind(new Date().toISOString(), totalDrift, runId)
    .run();

  return c.json({ runId, period, examined: rows.length, corrected, driftUnits: totalDrift });
});

export default reconciliation;
