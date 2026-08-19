'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const handlebars = require('handlebars');

const digests = require('../repositories/digests');
const { authenticate } = require('../auth/bearer');

const PORT = Number(process.env.DIGEST_PORT || 8121);
const PREVIEW_PATH = /^\/admin\/notifications\/digest\/preview$/;
const TEMPLATE_DIR = path.join(__dirname, '..', 'templates', 'email');
const LAYOUTS = ['weekly-digest', 'invoice-reminder', 'seat-limit'];

// Layouts ship with the release, so each one is read from disk and compiled
// once at boot. The request only chooses which layout to fill in.
const COMPILED = new Map(
  LAYOUTS.map((layout) => [
    layout,
    handlebars.compile(fs.readFileSync(path.join(TEMPLATE_DIR, `${layout}.hbs`), 'utf8')),
  ]),
);

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

function sendHtml(response, status, html) {
  response.writeHead(status, {
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store',
  });
  response.end(html);
}

async function renderPreview(request, response) {
  const actor = await authenticate(request);
  if (!actor || !actor.roles.includes('marketing')) {
    response.writeHead(403, { 'content-type': 'text/plain' });
    response.end('forbidden');
    return;
  }

  const draft = await readJson(request);
  const render = COMPILED.get(String(draft.layout));
  if (!render) {
    response.writeHead(400, { 'content-type': 'text/plain' });
    response.end(`unknown layout, expected one of ${LAYOUTS.join(', ')}`);
    return;
  }

  const html = render({
    subject: String(draft.subject || ''),
    headline: String(draft.headline || ''),
    intro: String(draft.intro || ''),
    recipient: { firstName: 'Ada', email: 'ada@example.com' },
    items: await digests.recentItems(actor.tenantId),
  });

  sendHtml(response, 200, html);
}

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);

  try {
    if (request.method === 'POST' && PREVIEW_PATH.test(url.pathname)) {
      await renderPreview(request, response);
      return;
    }
    if (request.method === 'GET' && url.pathname === '/admin/notifications/digest/layouts') {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ layouts: LAYOUTS }));
      return;
    }
    response.writeHead(404, { 'content-type': 'text/plain' });
    response.end('not found');
  } catch (error) {
    console.error('digest preview failed', error);
    response.writeHead(500, { 'content-type': 'text/plain' });
    response.end('internal error');
  }
});

server.listen(PORT);

module.exports = { server, renderPreview };
