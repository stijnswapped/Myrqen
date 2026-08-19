'use strict';

const http = require('node:http');
const crypto = require('node:crypto');

const operators = require('../repositories/operators');
const sessionStore = require('../repositories/session-store');
const { verifyPassword } = require('../auth/passwords');
const { rateLimit } = require('../services/rate-limit');

const PORT = Number(process.env.CONSOLE_PORT || 8141);
const SESSION_TTL_SECONDS = 8 * 3600;
const SESSION_ID_BYTES = 32;

function readJson(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    request.on('data', (chunk) => chunks.push(chunk));
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

function respond(response, status, payload, headers = {}) {
  response.writeHead(status, { 'content-type': 'application/json', ...headers });
  response.end(JSON.stringify(payload));
}

function nextSessionId() {
  return crypto.randomBytes(SESSION_ID_BYTES).toString('hex');
}

// Operators sign in with email and password; the session cookie is scoped to
// the console host and expires at the end of the shift.
async function signIn(request, response) {
  const body = await readJson(request);
  const email = String(body.email || '').trim().toLowerCase();

  const allowed = await rateLimit(`console-login:${email}`, 10, 900);
  if (!allowed) {
    respond(response, 429, { error: 'too many attempts, try again later' });
    return;
  }

  const operator = await operators.findByEmail(email);
  if (!operator || !(await verifyPassword(body.password, operator.passwordHash))) {
    respond(response, 401, { error: 'email or password is incorrect' });
    return;
  }

  const sessionId = nextSessionId();
  await sessionStore.put(sessionId, {
    operatorId: operator.id,
    createdAt: Date.now(),
    userAgent: request.headers['user-agent'] || '',
  }, SESSION_TTL_SECONDS);

  respond(response, 200, { operator: { id: operator.id, email: operator.email } }, {
    'set-cookie': `console_sid=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL_SECONDS}`,
  });
}

async function signOut(request, response) {
  const match = /(?:^|;\s*)console_sid=([^;]+)/.exec(request.headers.cookie || '');
  if (match) await sessionStore.remove(match[1]);
  respond(response, 204, {}, { 'set-cookie': 'console_sid=; Path=/; Max-Age=0' });
}

const ROUTES = [
  { method: 'POST', path: '/console/login', handler: signIn },
  { method: 'POST', path: '/console/logout', handler: signOut },
];

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
  const route = ROUTES.find((entry) => entry.method === request.method && entry.path === url.pathname);

  if (!route) {
    respond(response, 404, { error: 'not found' });
    return;
  }

  try {
    await route.handler(request, response);
  } catch (error) {
    console.error('console request failed', error);
    respond(response, 500, { error: 'internal error' });
  }
});

server.listen(PORT);

module.exports = { server, signIn };
