import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { HTTPException } from 'hono/http-exception';
import type { AppEnv } from './bindings';
import { PERIOD_PATTERN, currentPeriod } from './bindings';
import { apiKeyAuth, internalServiceAuth } from './middleware/apiKey';
import adjustments from './routes/adjustments';
import analytics from './routes/analytics';
import entitlements from './routes/entitlements';
import usageExports from './routes/exports';
import ingest from './routes/ingest';
import keys from './routes/keys';
import quota from './routes/quota';
import reconciliation from './routes/reconciliation';
import reports from './routes/reports';
import statements from './routes/statements';
import webhooks from './routes/webhooks';

const app = new Hono<AppEnv>();

app.use('*', async (c, next) => {
  c.set('requestId', c.req.header('cf-ray') ?? crypto.randomUUID());
  await next();
  c.header('x-request-id', c.get('requestId'));
});

// Only the console origin needs browser access; SDK traffic is server to server.
app.use(
  '/v1/*',
  cors({
    origin: ['https://app.tallymark.io'],
    allowHeaders: ['authorization', 'content-type', 'x-api-key'],
    allowMethods: ['GET', 'POST', 'PATCH', 'DELETE'],
    maxAge: 600,
  }),
);

app.use('/v1/*', apiKeyAuth());
app.use('/internal/*', internalServiceAuth());

// Sub-routers declare their own absolute paths, so mounting is a one-liner and the
// wrangler dev route table matches the published OpenAPI document.
app.route('/', ingest);
app.route('/', adjustments);
app.route('/', quota);
app.route('/', entitlements);
app.route('/', reports);
app.route('/', analytics);
app.route('/', usageExports);
app.route('/', statements);
app.route('/', keys);
app.route('/', webhooks);
app.route('/', reconciliation);

/** Snapshot for the billing pipeline; gated by the internal service middleware. */
app.get('/internal/usage-snapshot', async (c) => {
  const period = c.req.query('period') ?? currentPeriod();
  if (!PERIOD_PATTERN.test(period)) {
    return c.json({ error: 'period must be YYYY-MM' }, 400);
  }

  const result = await c.env.DB.prepare(
    `SELECT account_id, metric, SUM(quantity) AS total
       FROM usage_events
      WHERE substr(occurred_at, 1, 7) = ?1
   GROUP BY account_id, metric`,
  )
    .bind(period)
    .all<{ account_id: string; metric: string; total: number }>();

  return c.json({ period, requestedBy: c.get('internalService'), rows: result.results ?? [] });
});

app.get('/health', (c) => c.json({ status: 'ok', environment: c.env.ENVIRONMENT }));

app.onError((error, c) => {
  if (error instanceof HTTPException) {
    return error.getResponse();
  }
  // Details stay in the Workers log; the client gets the request id to quote.
  console.error(`request ${c.get('requestId')} failed`, error);
  return c.json({ error: 'internal_error', requestId: c.get('requestId') }, 500);
});

export default app;
