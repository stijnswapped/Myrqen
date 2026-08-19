'use strict';

const http = require('node:http');
const crypto = require('node:crypto');
const querystring = require('node:querystring');

const users = require('../repositories/users');
const confirmations = require('../repositories/confirmations');
const mailer = require('../services/mailer');
const sessions = require('../auth/sessions');
const { rateLimit } = require('../services/rate-limit');

const PORT = Number(process.env.PROFILE_PORT || 8131);
const TOKEN_TTL_MINUTES = 30;
const TOKEN_BYTES = 32;
const APP_ORIGIN = process.env.APP_ORIGIN || 'https://app.example.com';

function readForm(request) {
  return new Promise((resolve, reject) => {
    let buffered = '';
    request.setEncoding('utf8');
    request.on('data', (chunk) => {
      buffered += chunk;
      if (buffered.length > 4096) {
        request.destroy();
        reject(new Error('form too large'));
      }
    });
    request.on('end', () => resolve(querystring.parse(buffered)));
    request.on('error', reject);
  });
}

function respond(response, status, payload) {
  response.writeHead(status, { 'content-type': 'application/json' });
  response.end(JSON.stringify(payload));
}

function buildToken() {
  return crypto.randomBytes(TOKEN_BYTES).toString('base64url');
}

function fingerprint(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

// Changing the address on an account is confirmed from the new mailbox. The
// link is single use and only the digest of the token is stored.
async function requestEmailChange(request, response) {
  const session = await sessions.fromCookieHeader(request.headers.cookie);
  if (!session) {
    respond(response, 401, { error: 'sign in required' });
    return;
  }

  const form = await readForm(request);
  const email = String(form.email || '').trim().toLowerCase();
  if (!email.includes('@')) {
    respond(response, 400, { error: 'a valid email address is required' });
    return;
  }

  const allowed = await rateLimit(`email-change:${session.userId}`, 5, 3600);
  if (!allowed) {
    respond(response, 429, { error: 'too many attempts, try again later' });
    return;
  }

  const account = await users.findById(session.userId);
  const token = buildToken();
  await confirmations.create({
    userId: account.id,
    pendingEmail: email,
    tokenDigest: fingerprint(token),
    expiresAt: new Date(Date.now() + TOKEN_TTL_MINUTES * 60 * 1000),
  });

  await mailer.send(email, 'confirm-email-change', {
    firstName: account.firstName,
    link: `${APP_ORIGIN}/settings/email/confirm?token=${token}`,
    minutes: TOKEN_TTL_MINUTES,
  });

  respond(response, 202, { status: 'sent' });
}

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);

  if (request.method !== 'POST') {
    respond(response, 405, { error: 'method not allowed' });
    return;
  }

  try {
    switch (url.pathname) {
      case '/settings/email':
        await requestEmailChange(request, response);
        return;
      default:
        respond(response, 404, { error: 'not found' });
    }
  } catch (error) {
    console.error('profile request failed', error);
    respond(response, 500, { error: 'internal error' });
  }
});

server.listen(PORT);

module.exports = { server, requestEmailChange };
