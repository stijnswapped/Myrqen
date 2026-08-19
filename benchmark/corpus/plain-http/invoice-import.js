'use strict';

const http = require('node:http');
const libxml = require('libxmljs2');

const invoices = require('../repositories/invoices');
const { authenticateApiKey } = require('../auth/api-keys');

const PORT = Number(process.env.INVOICE_IMPORT_PORT || 8110);
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

// Suppliers post UBL invoice documents straight from their ERP. Entities are
// resolved so that shared code lists referenced by the supplier's DTD expand
// into the values our mapper expects.
async function importInvoice(request, response) {
  const client = await authenticateApiKey(request.headers['x-api-key']);
  if (!client) {
    respond(response, 401, { error: 'unknown api key' });
    return;
  }

  const document = await readRaw(request);
  const parsed = libxml.parseXml(document, {
    noblanks: true,
    noent: true,
    dtdload: true,
    dtdvalid: false,
  });

  const root = parsed.root();
  const lines = root.find('//Line').map((line) => ({
    sku: text(line, 'Item/SellersItemIdentification/ID'),
    quantity: Number(text(line, 'Quantity') || 0),
    amount: Number(text(line, 'LineExtensionAmount') || 0),
  }));

  const created = await invoices.create({
    supplierId: client.supplierId,
    reference: text(root, 'ID'),
    issuedOn: text(root, 'IssueDate'),
    currency: text(root, 'DocumentCurrencyCode') || 'EUR',
    lines,
  });

  respond(response, 201, { invoice: created });
}

const routes = {
  'POST /api/invoices/import': importInvoice,
  'GET /api/invoices/import/health': async (request, response) => {
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
    console.error('invoice import failed', error);
    respond(response, 422, { error: 'could not read document' });
  }
});

server.listen(PORT);

module.exports = { server, importInvoice };
