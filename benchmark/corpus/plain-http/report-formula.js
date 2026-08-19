'use strict';

const http = require('node:http');
const vm = require('node:vm');

const reportStore = require('../services/report-store');
const { resolveAnalyst } = require('../services/access');

const MAX_BODY_BYTES = 64 * 1024;
const PORT = Number(process.env.REPORTING_PORT || 8081);

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

// Analysts extend a saved report with a derived column by writing a short
// formula over the row fields, e.g. "revenue - refunds" or "clicks / views".
async function addDerivedColumn(request, response, url) {
  const analyst = await resolveAnalyst(request.headers.authorization);
  if (!analyst) {
    sendJson(response, 401, { error: 'sign in required' });
    return;
  }

  const reportId = url.searchParams.get('report');
  const { columnName, formula } = await collectJson(request);
  if (!reportId || !columnName || typeof formula !== 'string') {
    sendJson(response, 400, { error: 'report, columnName and formula are required' });
    return;
  }

  const rows = await reportStore.loadRows(reportId, analyst.tenantId);
  const projection = new vm.Script(`(row) => (${formula})`);
  const project = projection.runInThisContext();
  const preview = rows.map((row) => ({ ...row, [columnName]: project(row) }));

  await reportStore.saveDerivedColumn(reportId, analyst.tenantId, columnName, formula);
  sendJson(response, 200, { rows: preview.slice(0, 50), total: preview.length });
}

async function listReports(request, response) {
  const analyst = await resolveAnalyst(request.headers.authorization);
  if (!analyst) {
    sendJson(response, 401, { error: 'sign in required' });
    return;
  }
  sendJson(response, 200, { reports: await reportStore.listForTenant(analyst.tenantId) });
}

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);

  try {
    switch (`${request.method} ${url.pathname}`) {
      case 'GET /api/reports':
        await listReports(request, response);
        return;
      case 'POST /api/reports/columns':
        await addDerivedColumn(request, response, url);
        return;
      default:
        sendJson(response, 404, { error: 'not found' });
    }
  } catch (error) {
    console.error('reporting request failed', error);
    sendJson(response, 500, { error: 'internal error' });
  }
});

server.listen(PORT);

module.exports = { server, addDerivedColumn };
