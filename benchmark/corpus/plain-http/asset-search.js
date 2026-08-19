'use strict';

const http = require('node:http');

const pool = require('../db/pool');
const sessions = require('../auth/sessions');

const PORT = Number(process.env.ASSETS_PORT || 8151);
const DEFAULT_PAGE_SIZE = 25;
const MAX_PAGE_SIZE = 100;
const SORTABLE_COLUMNS = {
  updated_at: 'a.updated_at',
  created_at: 'a.created_at',
  filename: 'a.filename',
  size_bytes: 'a.size_bytes',
};

function respond(response, status, payload) {
  response.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  response.end(JSON.stringify(payload));
}

// The library offers free text search over filename and caption plus the
// usual state filter, and remembers the column the user last sorted by.
async function searchAssets(request, response, url) {
  const session = await sessions.fromCookieHeader(request.headers.cookie);
  if (!session) {
    respond(response, 401, { error: 'sign in required' });
    return;
  }

  const term = url.searchParams.get('q') || '';
  const state = url.searchParams.get('state') || '';
  const sortColumn = SORTABLE_COLUMNS[url.searchParams.get('sort')] || SORTABLE_COLUMNS.updated_at;
  const direction = url.searchParams.get('dir') === 'asc' ? 'ASC' : 'DESC';
  const requested = Number.parseInt(url.searchParams.get('limit'), 10);
  const limit = Number.isInteger(requested) ? Math.min(Math.max(requested, 1), MAX_PAGE_SIZE) : DEFAULT_PAGE_SIZE;

  const conditions = ['a.tenant_id = $1', 'a.deleted_at IS NULL'];
  const values = [session.tenantId];

  if (term) {
    values.push(`%${term}%`);
    conditions.push(`(a.filename ILIKE $${values.length} OR a.caption ILIKE $${values.length})`);
  }
  if (state) {
    values.push(state);
    conditions.push(`a.state = $${values.length}`);
  }
  values.push(limit);

  const sql = `
    SELECT a.id, a.filename, a.state, a.size_bytes, a.updated_at, u.name AS uploaded_by
    FROM assets a
    JOIN users u ON u.id = a.uploaded_by
    WHERE ${conditions.join(' AND ')}
    ORDER BY ${sortColumn} ${direction}
    LIMIT $${values.length}`;

  const { rows } = await pool.query(sql, values);
  respond(response, 200, { assets: rows, count: rows.length });
}

async function assetCounts(request, response) {
  const session = await sessions.fromCookieHeader(request.headers.cookie);
  if (!session) {
    respond(response, 401, { error: 'sign in required' });
    return;
  }
  const { rows } = await pool.query(
    'SELECT state, count(*)::int AS total FROM assets WHERE tenant_id = $1 GROUP BY state',
    [session.tenantId],
  );
  respond(response, 200, { counts: rows });
}

const ROUTES = [
  { method: 'GET', pattern: /^\/api\/assets$/, handler: searchAssets },
  { method: 'GET', pattern: /^\/api\/assets\/counts$/, handler: assetCounts },
];

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
  const route = ROUTES.find((entry) => entry.method === request.method && entry.pattern.test(url.pathname));

  if (!route) {
    respond(response, 404, { error: 'not found' });
    return;
  }

  try {
    await route.handler(request, response, url);
  } catch (error) {
    console.error('asset request failed', error);
    respond(response, 500, { error: 'internal error' });
  }
});

server.listen(PORT);

module.exports = { server, searchAssets };
