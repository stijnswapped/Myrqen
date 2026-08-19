'use strict';

const http = require('node:http');
const querystring = require('node:querystring');

const users = require('../repositories/users');
const resetTokens = require('../repositories/reset-tokens');
const mailer = require('../services/mailer');
const { rateLimit } = require('../services/rate-limit');

const PORT = Number(process.env.AUTH_PORT || 8130);
const TOKEN_TTL_MINUTES = 30;
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
  return Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
}

// A reset link is single use and expires after half an hour. The response is
// identical whether or not the address exists so the form cannot be used to
// enumerate accounts.
async function requestReset(request, response) {
  const form = await readForm(request);
  const email = String(form.email || '').trim().toLowerCase();
  if (!email.includes('@')) {
    respond(response, 400, { error: 'a valid email address is required' });
    return;
  }

  const allowed = await rateLimit(`reset:${email}`, 5, 3600);
  if (!allowed) {
    respond(response, 429, { error: 'too many attempts, try again later' });
    return;
  }

  const account = await users.findByEmail(email);
  if (account) {
    const token = buildToken();
    await resetTokens.create({
      userId: account.id,
      token,
      expiresAt: new Date(Date.now() + TOKEN_TTL_MINUTES * 60 * 1000),
    });
    await mailer.send(account.email, 'password-reset', {
      firstName: account.firstName,
      link: `${APP_ORIGIN}/reset?token=${token}`,
      minutes: TOKEN_TTL_MINUTES,
    });
  }

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
      case '/auth/password-reset':
        await requestReset(request, response);
        return;
      default:
        respond(response, 404, { error: 'not found' });
    }
  } catch (error) {
    console.error('auth request failed', error);
    respond(response, 500, { error: 'internal error' });
  }
});

server.listen(PORT);

module.exports = { server, requestReset };
