'use strict';

const http = require('node:http');
const libxml = require('libxmljs2');

const statements = require('../repositories/statements');
const { authenticateApiKey } = require('../auth/api-keys');

const PORT = Number(process.env.STATEMENT_IMPORT_PORT || 8111);
const MAX_DOCUMENT_BYTES = 4 * 1024 * 1024;

function readRaw(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let received = 0;
    request.on('data', (chunk) => {
      received += chunk.length;
      if (received > MAX_DOCUMENT_BYTES) {
        request.destroy();
        reject(new Error('document too large'));
        return;
      }
      chunks.push(chunk);
    });
    request.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    request.on('error', reject);
  });
}

function respond(response, status, payload) {
  response.writeHead(status, { 'content-type': 'application/json' });
  response.end(JSON.stringify(payload));
}

function text(node, selector) {
  const found = node.get(selector);
  return found ? found.text().trim() : '';
}

// Banks post CAMT.053 statements from their file transfer gateway. The
// document is self-contained: only the elements below are read, and the
// parser is pinned to the document body itself.
async function importStatement(request, response) {
  const client = await authenticateApiKey(request.headers['x-api-key']);
  if (!client) {
    respond(response, 401, { error: 'unknown api key' });
    return;
  }

  const document = await readRaw(request);
  const parsed = libxml.parseXml(document, {
    noblanks: true,
    noent: false,
    nonet: true,
    dtdload: false,
    dtdattr: false,
    dtdvalid: false,
  });

  const root = parsed.root();
  const entries = root.find('//Ntry').map((entry) => ({
    bookedOn: text(entry, 'BookgDt/Dt'),
    amount: Number(text(entry, 'Amt') || 0),
    direction: text(entry, 'CdtDbtInd') === 'CRDT' ? 'credit' : 'debit',
    reference: text(entry, 'NtryRef'),
  }));

  const created = await statements.create({
    accountId: client.accountId,
    iban: text(root, 'Acct/Id/IBAN'),
    currency: text(root, 'Acct/Ccy') || 'EUR',
    entries,
  });

  respond(response, 201, { statement: created });
}

const routes = {
  'POST /api/statements/import': importStatement,
  'GET /api/statements/import/health': async (request, response) => {
    respond(response, 200, { ok: true, parser: 'libxml2' });
  },
};

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
  const handler = routes[`${request.method} ${url.pathname}`];

  if (!handler) {
    respond(response, 404, { error: 'not found' });
    return;
  }

  try {
    await handler(request, response);
  } catch (error) {
    console.error('statement import failed', error);
    respond(response, 422, { error: 'could not read document' });
  }
});

server.listen(PORT);

module.exports = { server, importStatement };
