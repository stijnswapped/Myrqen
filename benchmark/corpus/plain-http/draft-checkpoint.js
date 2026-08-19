'use strict';

const http = require('node:http');

const drafts = require('../repositories/drafts');
const sessions = require('../auth/sessions');

const PORT = Number(process.env.CHECKPOINT_PORT || 8091);
const MAX_SNAPSHOT_BYTES = 512 * 1024;
const MAX_TITLE_LENGTH = 200;
const MAX_BODY_LENGTH = 200 * 1024;

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
  response.writeHead(status, { 'content-type': 'application/json' });
  response.end(JSON.stringify(payload));
}

async function currentEditor(request) {
  const cookie = request.headers.cookie || '';
  const match = /(?:^|;\s*)editor_sid=([^;]+)/.exec(cookie);
  return match ? sessions.lookup(decodeURIComponent(match[1])) : null;
}

// A checkpoint carries only these four fields; anything else the client
// happens to send is dropped rather than reconstructed.
function readCheckpoint(text) {
  const raw = JSON.parse(text);
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  if (typeof raw.draftId !== 'string' || !/^[0-9a-f-]{36}$/.test(raw.draftId)) return null;
  if (typeof raw.title !== 'string' || raw.title.length > MAX_TITLE_LENGTH) return null;
  if (typeof raw.body !== 'string' || raw.body.length > MAX_BODY_LENGTH) return null;
  if (!Number.isInteger(raw.revision) || raw.revision < 0) return null;
  return { draftId: raw.draftId, title: raw.title, body: raw.body, revision: raw.revision };
}

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
  const snapshot = readCheckpoint(encoded);
  if (!snapshot) {
    reply(response, 422, { error: 'snapshot is not a valid checkpoint' });
    return;
  }

  const stored = await drafts.findById(snapshot.draftId, editor.id);
  if (!stored) {
    reply(response, 404, { error: 'draft not found' });
    return;
  }

  const merged = await drafts.merge(stored.id, {
    body: snapshot.body,
    title: snapshot.title,
    revision: Math.max(stored.revision, snapshot.revision) + 1,
    updatedAt: new Date(),
  });

  reply(response, 200, { draft: merged });
}

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
  const target = url.pathname.replace(/\/+$/, '');

  try {
    if (request.method === 'POST' && target === '/editor/drafts/checkpoint') {
      await resumeDraft(request, response);
      return;
    }
    if (request.method === 'GET' && target === '/editor/health') {
      reply(response, 200, { ok: true });
      return;
    }
    reply(response, 404, { error: 'not found' });
  } catch (error) {
    console.error('checkpoint request failed', error);
    reply(response, 500, { error: 'internal error' });
  }
});

server.listen(PORT);

module.exports = { server, resumeDraft };
