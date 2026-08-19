'use strict';

const http = require('node:http');

const accounts = require('../repositories/accounts');
const { authenticate } = require('../auth/bearer');

const PORT = Number(process.env.ACCOUNT_PREFERENCES_PORT || 8101);
const ACCOUNT_PREFERENCES = /^\/api\/accounts\/([0-9a-zA-Z_-]{6,40})\/preferences$/;
const RESERVED_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

const DEFAULT_PREFERENCES = {
  theme: 'system',
  locale: 'en-GB',
  notifications: { digest: 'daily', mentions: true, deploys: false },
  editor: { tabWidth: 2, wrap: true, minimap: false },
};

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

function respond(response, status, payload) {
  response.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  response.end(JSON.stringify(payload));
}

// Preferences arrive as a partial tree so the UI can patch one nested toggle
// without shipping the whole document back.
function applyPatch(target, patch) {
  for (const key of Object.keys(patch)) {
    if (RESERVED_KEYS.has(key)) continue;
    const value = patch[key];
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      if (!Object.hasOwn(target, key) || typeof target[key] !== 'object' || target[key] === null) {
        target[key] = Object.create(null);
      }
      applyPatch(target[key], value);
    } else {
      target[key] = value;
    }
  }
  return target;
}

function toPlainTree(source) {
  const copy = Object.create(null);
  for (const key of Object.keys(source)) {
    const value = source[key];
    copy[key] = value && typeof value === 'object' && !Array.isArray(value) ? toPlainTree(value) : value;
  }
  return copy;
}

async function patchPreferences(request, response, accountId) {
  const actor = await authenticate(request);
  if (!actor || actor.accountId !== accountId) {
    respond(response, 403, { error: 'insufficient permissions' });
    return;
  }

  const patch = await readJson(request);
  const stored = await accounts.loadPreferences(accountId);
  const merged = applyPatch(toPlainTree({ ...DEFAULT_PREFERENCES, ...stored }), patch);

  await accounts.savePreferences(accountId, merged);
  respond(response, 200, { preferences: { ...merged } });
}

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
  const preferences = ACCOUNT_PREFERENCES.exec(url.pathname);

  try {
    if (preferences && request.method === 'PATCH') {
      await patchPreferences(request, response, preferences[1]);
      return;
    }
    if (preferences && request.method === 'GET') {
      const stored = await accounts.loadPreferences(preferences[1]);
      respond(response, 200, { preferences: { ...DEFAULT_PREFERENCES, ...stored } });
      return;
    }
    respond(response, 404, { error: 'not found' });
  } catch (error) {
    console.error('account preferences request failed', error);
    respond(response, 500, { error: 'internal error' });
  }
});

server.listen(PORT);

module.exports = { server, patchPreferences, applyPatch };
