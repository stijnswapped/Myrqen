'use strict';

const http = require('node:http');

const orders = require('../repositories/orders');
const products = require('../repositories/products');
const shipping = require('../services/shipping');
const payments = require('../services/payments');
const sessions = require('../auth/sessions');

const PORT = Number(process.env.ORDERS_PORT || 8171);
const MAX_BODY_BYTES = 32 * 1024;
const MAX_UNITS_PER_LINE = 10;
const MAX_LINES = 50;

function readJson(request) {
  return new Promise((resolve, reject) => {
    let buffered = '';
    request.setEncoding('utf8');
    request.on('data', (chunk) => {
      buffered += chunk;
      if (buffered.length > MAX_BODY_BYTES) {
        request.destroy();
        reject(new Error('payload too large'));
      }
    });
    request.on('end', () => {
      try {
        resolve(JSON.parse(buffered || '{}'));
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
// session; on checkout the client posts which article it wants and how many,
// and the amounts are taken from the catalogue.
async function placeOrder(request, response) {
  const session = await sessions.fromCookieHeader(request.headers.cookie);
  const basket = await readJson(request);
  if (!Array.isArray(basket.items) || basket.items.length === 0) {
    respond(response, 400, { error: 'basket is empty' });
    return;
  }
  if (basket.items.length > MAX_LINES) {
    respond(response, 422, { error: `a basket holds at most ${MAX_LINES} lines` });
    return;
  }
  const catalogue = await products.findBySkus(basket.items.map((item) => String(item.sku)));
  const bySku = new Map(catalogue.map((product) => [product.sku, product]));
  const lines = [];

  for (const item of basket.items) {
    const product = bySku.get(String(item.sku));
    const units = Number.parseInt(item.quantity, 10);
    if (!product || !product.isPurchasable) {
      respond(response, 422, { error: `article ${item.sku} is not available` });
      return;
    }
    if (!Number.isInteger(units) || units < 1 || units > MAX_UNITS_PER_LINE) {
      respond(response, 422, { error: `quantity for ${product.sku} must be 1-${MAX_UNITS_PER_LINE}` });
      return;
    }
    lines.push({
      sku: product.sku,
      name: product.name,
      quantity: units,
      unitPriceCents: product.priceCents,
      lineTotalCents: product.priceCents * units,
    });
  }

  const subtotalCents = lines.reduce((sum, line) => sum + line.lineTotalCents, 0);
  const shippingCents = await shipping.priceFor(String(basket.shippingOption || 'standard'), lines);
  const totalCents = subtotalCents + shippingCents;

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
    if (request.method === 'POST' && url.pathname === '/api/orders') {
      await placeOrder(request, response);
      return;
    }
    respond(response, 404, { error: 'not found' });
  } catch (error) {
    console.error('order submission failed', error);
    respond(response, 500, { error: 'internal error' });
  }
});

server.listen(PORT);

module.exports = { server, placeOrder };
