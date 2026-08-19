'use strict';

const http = require('node:http');

const workspaces = require('../repositories/workspaces');
const { authenticate } = require('../auth/bearer');

const PORT = Number(process.env.PREFERENCES_PORT || 8100);
const WORKSPACE_PREFERENCES = /^\/api\/workspaces\/([0-9a-zA-Z_-]{6,40})\/preferences$/;

const DEFAULT_PREFERENCES = {
  theme: 'system',
  locale: 'en-GB',
  notifications: { digest: 'daily', mentions: true, deploys: false },
  editor: { tabWidth: 2, wrap: true, minimap: false },
  features: { betaSearch: false, aiSummaries: false },
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
    const value = patch[key];
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      if (typeof target[key] !== 'object' || target[key] === null) {
        target[key] = {};
      }
      applyPatch(target[key], value);
    } else {
      target[key] = value;
    }
  }
  return target;
}

async function patchPreferences(request, response, workspaceId) {
  const actor = await authenticate(request);
  if (!actor) {
    respond(response, 401, { error: 'authentication required' });
    return;
  }

  const membership = await workspaces.findMembership(workspaceId, actor.id);
  if (!membership || membership.role === 'viewer') {
    respond(response, 403, { error: 'insufficient permissions' });
    return;
  }

  const patch = await readJson(request);
  const stored = await workspaces.loadPreferences(workspaceId);
  const merged = applyPatch({ ...DEFAULT_PREFERENCES, ...stored }, patch);

  await workspaces.savePreferences(workspaceId, merged);
  respond(response, 200, { preferences: merged });
}

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
  const preferences = WORKSPACE_PREFERENCES.exec(url.pathname);

  try {
    if (preferences && request.method === 'PATCH') {
      await patchPreferences(request, response, preferences[1]);
      return;
    }
    if (preferences && request.method === 'GET') {
      const stored = await workspaces.loadPreferences(preferences[1]);
      respond(response, 200, { preferences: { ...DEFAULT_PREFERENCES, ...stored } });
      return;
    }
    respond(response, 404, { error: 'not found' });
  } catch (error) {
    console.error('preferences request failed', error);
    respond(response, 500, { error: 'internal error' });
  }
});

server.listen(PORT);

module.exports = { server, patchPreferences, applyPatch };
