'use strict';

const http = require('node:http');
const crypto = require('node:crypto');

const users = require('../repositories/users');
const sessionStore = require('../repositories/session-store');
const { verifyPassword } = require('../auth/passwords');

const PORT = Number(process.env.PORTAL_PORT || 8140);
const SESSION_TTL_SECONDS = 12 * 3600;

let issuedCount = 0;

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

function nextSessionId(account) {
  issuedCount += 1;
  const seed = `${account.id}:${issuedCount}:${Date.now()}`;
  return crypto.createHash('md5').update(seed).digest('hex');
}

// Customers sign in with email and password; the session cookie is scoped to
// the portal host and expires with the working day.
async function signIn(request, response) {
  const body = await readJson(request);
  const email = String(body.email || '').trim().toLowerCase();
  const account = await users.findByEmail(email);
  if (!account || !(await verifyPassword(body.password, account.passwordHash))) {
    respond(response, 401, { error: 'email or password is incorrect' });
    return;
  }

  const sessionId = nextSessionId(account);
  await sessionStore.put(sessionId, {
    userId: account.id,
    createdAt: Date.now(),
    userAgent: request.headers['user-agent'] || '',
  }, SESSION_TTL_SECONDS);

  respond(response, 200, { user: { id: account.id, email: account.email } }, {
    'set-cookie': `portal_sid=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_TTL_SECONDS}`,
  });
}

async function signOut(request, response) {
  const match = /(?:^|;\s*)portal_sid=([^;]+)/.exec(request.headers.cookie || '');
  if (match) await sessionStore.remove(match[1]);
  respond(response, 204, {}, { 'set-cookie': 'portal_sid=; Path=/; Max-Age=0' });
}

const ROUTES = [
  { method: 'POST', path: '/portal/login', handler: signIn },
  { method: 'POST', path: '/portal/logout', handler: signOut },
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
    console.error('portal request failed', error);
    respond(response, 500, { error: 'internal error' });
  }
});

server.listen(PORT);

module.exports = { server, signIn };
