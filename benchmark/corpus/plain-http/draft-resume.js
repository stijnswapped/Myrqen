'use strict';

const http = require('node:http');
const serialize = require('node-serialize');

const drafts = require('../repositories/drafts');
const sessions = require('../auth/sessions');

const PORT = Number(process.env.EDITOR_PORT || 8090);
const MAX_SNAPSHOT_BYTES = 512 * 1024;

function readBody(request, limit) {
  return new Promise((resolve, reject) => {
    let buffered = '';
    request.setEncoding('utf8');
    request.on('data', (chunk) => {
      buffered += chunk;
      if (buffered.length > limit) {
        request.destroy();
        reject(new Error('snapshot too large'));
      }
    });
    request.on('end', () => resolve(buffered));
    request.on('error', reject);
  });
}

function reply(response, status, payload) {
  const body = JSON.stringify(payload);
  response.writeHead(status, { 'content-type': 'application/json' });
  response.end(body);
}

async function currentEditor(request) {
  const cookie = request.headers.cookie || '';
  const match = /(?:^|;\s*)editor_sid=([^;]+)/.exec(cookie);
  return match ? sessions.lookup(decodeURIComponent(match[1])) : null;
}

// The editor keeps an offline snapshot of the working copy in local storage.
// When the tab reconnects it posts the snapshot back so the server can merge
// it with whatever was persisted while the client was away.
async function resumeDraft(request, response) {
  const editor = await currentEditor(request);
  if (!editor) {
    reply(response, 401, { error: 'session expired' });
    return;
  }

  const payload = JSON.parse(await readBody(request, MAX_SNAPSHOT_BYTES) || '{}');
  if (typeof payload.snapshot !== 'string') {
    reply(response, 400, { error: 'snapshot is required' });
    return;
  }

  const encoded = Buffer.from(payload.snapshot, 'base64').toString('utf8');
  const snapshot = serialize.unserialize(encoded);

  const stored = await drafts.findById(snapshot.draftId, editor.id);
  if (!stored) {
    reply(response, 404, { error: 'draft not found' });
    return;
  }

  const merged = await drafts.merge(stored.id, {
    body: snapshot.body,
    title: snapshot.title,
    revision: Math.max(stored.revision, Number(snapshot.revision) || 0) + 1,
    updatedAt: new Date(),
  });

  reply(response, 200, { draft: merged });
}

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
  const target = url.pathname.replace(/\/+$/, '');

  try {
    if (request.method === 'POST' && target === '/editor/drafts/resume') {
      await resumeDraft(request, response);
      return;
    }
    if (request.method === 'GET' && target === '/editor/health') {
      reply(response, 200, { ok: true });
      return;
    }
    reply(response, 404, { error: 'not found' });
  } catch (error) {
    console.error('editor request failed', error);
    reply(response, 500, { error: 'internal error' });
  }
});

server.listen(PORT);

module.exports = { server, resumeDraft };
