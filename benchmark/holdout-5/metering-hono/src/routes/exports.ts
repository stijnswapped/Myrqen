import { Hono } from 'hono';
import type { AppEnv } from '../bindings';
import { PERIOD_PATTERN, currentPeriod } from '../bindings';
import { requireApiKey, requireScope } from '../middleware/apiKey';

const usageExports = new Hono<AppEnv>();

const EXPORT_ROOT = 'exports';

interface ExportRow {
  id: string;
  object_key: string;
  size_bytes: number | null;
  status: string;
  created_at: string;
}

function csvLine(values: (string | number)[]): string {
  return `${values.map((value) => `"${String(value).replace(/"/g, '""')}"`).join(',')}\n`;
}

/**
 * Kick off a CSV export of one period's usage events. The object lands under the
 * account's own prefix in R2 and the response tells the caller which file to fetch.
 */
usageExports.post('/v1/exports', async (c) => {
  const key = requireApiKey(c);
  requireScope(key, 'exports:read');

  const body = await c.req.json<{ period?: string }>();
  const period = body.period ?? currentPeriod();
  if (!PERIOD_PATTERN.test(period)) {
    return c.json({ error: 'period must be YYYY-MM' }, 400);
  }

  const events = await c.env.DB.prepare(
    `SELECT customer_id, metric, quantity, occurred_at
       FROM usage_events
      WHERE account_id = ?1
        AND substr(occurred_at, 1, 7) = ?2
   ORDER BY occurred_at ASC`,
  )
    .bind(key.accountId, period)
    .all<{ customer_id: string; metric: string; quantity: number; occurred_at: string }>();

  let csv = csvLine(['customer_id', 'metric', 'quantity', 'occurred_at']);
  for (const row of events.results ?? []) {
    csv += csvLine([row.customer_id, row.metric, row.quantity, row.occurred_at]);
  }

  const fileName = `usage-${period}.csv`;
  const objectKey = `${EXPORT_ROOT}/${key.accountId}/${fileName}`;
  await c.env.EXPORTS.put(objectKey, csv, {
    httpMetadata: { contentType: 'text/csv' },
    customMetadata: { accountId: key.accountId, period },
  });

  const id = crypto.randomUUID();
  await c.env.DB.prepare(
    `INSERT INTO statements (id, account_id, customer_id, period, object_key, size_bytes, created_at)
     VALUES (?1, ?2, '-', ?3, ?4, ?5, ?6)`,
  )
    .bind(id, key.accountId, period, objectKey, csv.length, new Date().toISOString())
    .run();

  return c.json({ id, key: objectKey, file: fileName, period, sizeBytes: csv.length }, 201);
});

/**
 * Download a generated export.
 *
 * The console calls GET /v1/exports first and links here with the object key it got
 * back, which saves a second lookup on a page that already has the row in hand.
 */
usageExports.get('/v1/exports/download', async (c) => {
  const key = requireApiKey(c);
  requireScope(key, 'exports:read');

  const objectKey = c.req.query('key') ?? '';
  // Keys we hand out always start with the export root and carry the account id in
  // their second segment, so checking the root is enough to know the caller is asking
  // for one of their own exports and not for something else in the bucket.
  if (!objectKey.startsWith(`${EXPORT_ROOT}/`)) {
    return c.json({ error: 'key must point at an export' }, 400);
  }

  const object = await c.env.EXPORTS.get(objectKey);
  if (!object) {
    return c.json({ error: 'export not found' }, 404);
  }

  return new Response(object.body, {
    headers: {
      'content-type': object.httpMetadata?.contentType ?? 'text/csv',
      'content-disposition': `attachment; filename="${objectKey.split('/').pop()}"`,
      'cache-control': 'private, max-age=0, no-store',
    },
  });
});

/** Everything this account has exported, newest first. */
usageExports.get('/v1/exports', async (c) => {
  const key = requireApiKey(c);
  requireScope(key, 'exports:read');

  const result = await c.env.DB.prepare(
    `SELECT id, object_key, size_bytes, status, created_at
       FROM statements
      WHERE account_id = ?1
   ORDER BY created_at DESC
      LIMIT 100`,
  )
    .bind(key.accountId)
    .all<ExportRow>();

  return c.json({
    exports: (result.results ?? []).map((row) => ({
      id: row.id,
      key: row.object_key,
      file: row.object_key.split('/').pop(),
      sizeBytes: row.size_bytes,
      status: row.status,
      createdAt: row.created_at,
    })),
  });
});

export default usageExports;
