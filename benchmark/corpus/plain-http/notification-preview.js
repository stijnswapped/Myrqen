'use strict';

const http = require('node:http');
const handlebars = require('handlebars');

const templates = require('../repositories/notification-templates');
const { authenticate } = require('../auth/bearer');

const PORT = Number(process.env.NOTIFICATIONS_PORT || 8120);
const PREVIEW_PATH = /^\/admin\/notifications\/[a-z0-9-]+\/preview$/;
const MAX_TEMPLATE_BYTES = 128 * 1024;

const PREVIEW_CONTEXT = {
  recipient: { firstName: 'Ada', email: 'ada@example.com', plan: 'team' },
  invoice: { number: 'INV-2043', total: '€ 148,00', dueOn: '2024-08-01' },
  workspace: { name: 'Northwind', seats: 12 },
};

function readJson(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let received = 0;
    request.on('data', (chunk) => {
      received += chunk.length;
      if (received > MAX_TEMPLATE_BYTES) {
        request.destroy();
        reject(new Error('template too large'));
        return;
      }
      chunks.push(chunk);
    });
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

// The template editor posts the draft markup on every keystroke so the
// right-hand pane can show what the email will look like with placeholder data.
async function renderPreview(request, response, slug) {
  const actor = await authenticate(request);
  if (!actor || !actor.roles.includes('marketing')) {
    response.writeHead(403, { 'content-type': 'text/plain' });
    response.end('forbidden');
    return;
  }

  const draft = await readJson(request);
  const markup = typeof draft.body === 'string' ? draft.body : '';
  const render = handlebars.compile(markup);
  const html = render({ ...PREVIEW_CONTEXT, subject: draft.subject || '' });

  await templates.saveDraft(slug, actor.id, { subject: draft.subject, body: markup });
  sendHtml(response, 200, html);
}

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);

  try {
    if (request.method === 'POST' && PREVIEW_PATH.test(url.pathname)) {
      const slug = url.pathname.split('/')[3];
      await renderPreview(request, response, slug);
      return;
    }
    response.writeHead(404, { 'content-type': 'text/plain' });
    response.end('not found');
  } catch (error) {
    console.error('preview failed', error);
    response.writeHead(500, { 'content-type': 'text/plain' });
    response.end('internal error');
  }
});

server.listen(PORT);

module.exports = { server, renderPreview };
