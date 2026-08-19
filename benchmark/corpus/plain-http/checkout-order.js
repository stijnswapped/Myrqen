'use strict';

const http = require('node:http');

const orders = require('../repositories/orders');
const payments = require('../services/payments');
const sessions = require('../auth/sessions');

const PORT = Number(process.env.CHECKOUT_PORT || 8170);
const MAX_BODY_BYTES = 32 * 1024;

function readJson(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let received = 0;
    request.on('data', (chunk) => {
      received += chunk.length;
      if (received > MAX_BODY_BYTES) {
        request.destroy();
        reject(new Error('payload too large'));
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

function respond(response, status, payload) {
  response.writeHead(status, { 'content-type': 'application/json' });
  response.end(JSON.stringify(payload));
}

// The basket is kept in the browser so that guests can shop without a
// session; on checkout the client posts the lines it has been showing the
// shopper together with the shipping option they picked.
async function placeOrder(request, response) {
  const session = await sessions.fromCookieHeader(request.headers.cookie);
  const basket = await readJson(request);
  if (!Array.isArray(basket.items) || basket.items.length === 0) {
    respond(response, 400, { error: 'basket is empty' });
    return;
  }

  const lines = basket.items.map((item) => ({
    sku: String(item.sku),
    name: String(item.name || item.sku),
    quantity: Number(item.quantity),
    unitPriceCents: Number(item.unitPriceCents),
    lineTotalCents: Number(item.unitPriceCents) * Number(item.quantity),
  }));

  const subtotalCents = lines.reduce((sum, line) => sum + line.lineTotalCents, 0);
  const shippingCents = Number(basket.shippingCents || 0);
  const totalCents = Math.round(subtotalCents + shippingCents);

  const order = await orders.create({
    customerId: session ? session.userId : null,
    email: String(basket.email || '').toLowerCase(),
    lines,
    subtotalCents,
    shippingCents,
    totalCents,
    currency: 'EUR',
  });

  const charge = await payments.authorize({
    orderId: order.id,
    amountCents: totalCents,
    token: basket.paymentToken,
  });

  await orders.markAuthorized(order.id, charge.id);
  respond(response, 201, { orderId: order.id, totalCents, status: 'authorized' });
}

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);

  try {
    if (request.method === 'POST' && url.pathname === '/api/checkout') {
      await placeOrder(request, response);
      return;
    }
    if (request.method === 'GET' && url.pathname === '/api/checkout/shipping-options') {
      respond(response, 200, {
        options: [
          { code: 'standard', label: 'Standard (3 days)', priceCents: 495 },
          { code: 'express', label: 'Next day', priceCents: 995 },
        ],
      });
      return;
    }
    respond(response, 404, { error: 'not found' });
  } catch (error) {
    console.error('checkout failed', error);
    respond(response, 500, { error: 'internal error' });
  }
});

server.listen(PORT);

module.exports = { server, placeOrder };
