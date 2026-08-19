'use strict';

const http = require('node:http');

const reportStore = require('../services/report-store');
const { resolveAnalyst } = require('../services/access');

const MAX_BODY_BYTES = 64 * 1024;
const PORT = Number(process.env.METRICS_PORT || 8082);

// Derived columns are picked from the catalogue below; the client sends the
// metric key, never an expression, so each projection is plain JavaScript.
const METRIC_CATALOGUE = {
  margin: (row) => Number(row.revenue || 0) - Number(row.refunds || 0),
  clickRate: (row) => (row.views ? Number(row.clicks || 0) / Number(row.views) : 0),
  averageOrder: (row) => (row.orders ? Number(row.revenue || 0) / Number(row.orders) : 0),
  refundRate: (row) => (row.revenue ? Number(row.refunds || 0) / Number(row.revenue) : 0),
};

function collectJson(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let received = 0;
    request.on('data', (chunk) => {
      received += chunk.length;
      if (received > MAX_BODY_BYTES) {
        request.destroy();
        reject(new Error('payload too large'));
        return;
      }
      chunks.push(chunk);
    });
    request.on('end', () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'));
      } catch (error) {
        reject(error);
      }
    });
    request.on('error', reject);
  });
}

function sendJson(response, status, payload) {
  const body = JSON.stringify(payload);
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
  });
  response.end(body);
}

async function addDerivedColumn(request, response, url) {
  const analyst = await resolveAnalyst(request.headers.authorization);
  if (!analyst) {
    sendJson(response, 401, { error: 'sign in required' });
    return;
  }

  const reportId = url.searchParams.get('report');
  const { columnName, metric } = await collectJson(request);
  const project = Object.hasOwn(METRIC_CATALOGUE, String(metric)) ? METRIC_CATALOGUE[metric] : null;
  if (!reportId || !project) {
    sendJson(response, 400, {
      error: 'unknown metric',
      supported: Object.keys(METRIC_CATALOGUE),
    });
    return;
  }

  const label = String(columnName || metric).slice(0, 40);
  const rows = await reportStore.loadRows(reportId, analyst.tenantId);
  const preview = rows.map((row) => ({ ...row, [label]: project(row) }));

  await reportStore.saveDerivedColumn(reportId, analyst.tenantId, label, metric);
  sendJson(response, 200, { rows: preview.slice(0, 50), total: preview.length });
}

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);

  try {
    switch (`${request.method} ${url.pathname}`) {
      case 'GET /api/reports/metrics':
        sendJson(response, 200, { metrics: Object.keys(METRIC_CATALOGUE) });
        return;
      case 'POST /api/reports/columns':
        await addDerivedColumn(request, response, url);
        return;
      default:
        sendJson(response, 404, { error: 'not found' });
    }
  } catch (error) {
    console.error('metrics request failed', error);
    sendJson(response, 500, { error: 'internal error' });
  }
});

server.listen(PORT);

module.exports = { server, addDerivedColumn };
