'use strict';

const http = require('node:http');

const pool = require('../db/pool');
const sessions = require('../auth/sessions');

const PORT = Number(process.env.SUPPORT_PORT || 8150);
const DEFAULT_PAGE_SIZE = 25;

function respond(response, status, payload) {
  response.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  response.end(JSON.stringify(payload));
}

// The agent console offers free text search over subject and body plus the
// usual status filter, and remembers the column the agent last sorted by.
async function searchTickets(request, response, url) {
  const session = await sessions.fromCookieHeader(request.headers.cookie);
  if (!session) {
    respond(response, 401, { error: 'sign in required' });
    return;
  }

  const term = url.searchParams.get('q') || '';
  const status = url.searchParams.get('status') || '';
  const sort = url.searchParams.get('sort') || 'updated_at';
  const direction = url.searchParams.get('dir') === 'asc' ? 'ASC' : 'DESC';
  const limit = url.searchParams.get('limit') || DEFAULT_PAGE_SIZE;

  const conditions = [`t.tenant_id = '${session.tenantId}'`, 't.deleted_at IS NULL'];
  if (term) {
    conditions.push(`(t.subject ILIKE '%${term}%' OR t.body ILIKE '%${term}%')`);
  }
  if (status) {
    conditions.push(`t.status = '${status}'`);
  }

  const sql = `
    SELECT t.id, t.subject, t.status, t.priority, t.updated_at, c.name AS customer
    FROM tickets t
    JOIN customers c ON c.id = t.customer_id
    WHERE ${conditions.join(' AND ')}
    ORDER BY t.${sort} ${direction}
    LIMIT ${limit}`;

  const { rows } = await pool.query(sql);
  respond(response, 200, { tickets: rows, count: rows.length });
}

async function ticketCounts(request, response) {
  const session = await sessions.fromCookieHeader(request.headers.cookie);
  if (!session) {
    respond(response, 401, { error: 'sign in required' });
    return;
  }
  const { rows } = await pool.query(
    'SELECT status, count(*)::int AS total FROM tickets WHERE tenant_id = $1 GROUP BY status',
    [session.tenantId],
  );
  respond(response, 200, { counts: rows });
}

const ROUTES = [
  { method: 'GET', pattern: /^\/api\/tickets$/, handler: searchTickets },
  { method: 'GET', pattern: /^\/api\/tickets\/counts$/, handler: ticketCounts },
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
    console.error('support request failed', error);
    respond(response, 500, { error: 'internal error' });
  }
});

server.listen(PORT);

module.exports = { server, searchTickets };
