'use strict';

const http = require('node:http');

const pool = require('../db/pool');
const payouts = require('../services/payouts');
const { authenticate } = require('../auth/bearer');

const PORT = Number(process.env.WALLET_PORT || 8180);
const MIN_WITHDRAWAL_CENTS = 500;

function readJson(request) {
  return new Promise((resolve, reject) => {
    let buffered = '';
    request.setEncoding('utf8');
    request.on('data', (chunk) => {
      buffered += chunk;
      if (buffered.length > 8192) {
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

// Riders cash out their earnings to the bank account on file. The payout is
// queued for the nightly batch and the wallet is debited straight away so the
// app shows the new balance on the next poll.
async function requestWithdrawal(request, response) {
  const actor = await authenticate(request);
  if (!actor) {
    respond(response, 401, { error: 'authentication required' });
    return;
  }

  const body = await readJson(request);
  const amountCents = Number.parseInt(body.amountCents, 10);
  if (!Number.isInteger(amountCents) || amountCents < MIN_WITHDRAWAL_CENTS) {
    respond(response, 422, { error: `minimum withdrawal is ${MIN_WITHDRAWAL_CENTS} cents` });
    return;
  }

  const wallet = await pool.query(
    'SELECT id, balance_cents, payout_account_id FROM wallets WHERE rider_id = $1',
    [actor.id],
  );
  const account = wallet.rows[0];
  if (!account) {
    respond(response, 404, { error: 'wallet not found' });
    return;
  }
  if (account.balance_cents < amountCents) {
    respond(response, 402, { error: 'insufficient balance' });
    return;
  }

  await pool.query(
    'UPDATE wallets SET balance_cents = $1, updated_at = now() WHERE id = $2',
    [account.balance_cents - amountCents, account.id],
  );

  const payout = await payouts.enqueue({
    walletId: account.id,
    payoutAccountId: account.payout_account_id,
    amountCents,
  });

  await pool.query(
    'INSERT INTO wallet_entries (wallet_id, kind, amount_cents, reference) VALUES ($1, $2, $3, $4)',
    [account.id, 'withdrawal', -amountCents, payout.id],
  );

  respond(response, 202, {
    payoutId: payout.id,
    balanceCents: account.balance_cents - amountCents,
  });
}

const ROUTES = new Map([
  ['POST /api/wallet/withdrawals', requestWithdrawal],
]);

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
  const handler = ROUTES.get(`${request.method} ${url.pathname}`);

  if (!handler) {
    respond(response, 404, { error: 'not found' });
    return;
  }

  try {
    await handler(request, response);
  } catch (error) {
    console.error('withdrawal failed', error);
    respond(response, 500, { error: 'internal error' });
  }
});

server.listen(PORT);

module.exports = { server, requestWithdrawal };
