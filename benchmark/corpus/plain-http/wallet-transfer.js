'use strict';

const http = require('node:http');

const pool = require('../db/pool');
const payouts = require('../services/payouts');
const { authenticate } = require('../auth/bearer');

const PORT = Number(process.env.TRANSFER_PORT || 8181);
const MIN_TRANSFER_CENTS = 500;

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

// Riders move earnings to their bank account. The client sends a request key
// so a retried tap resolves to the same transfer, and the debit is settled in
// one statement inside the transaction that queues the payout.
async function requestTransfer(request, response) {
  const actor = await authenticate(request);
  if (!actor) {
    respond(response, 401, { error: 'authentication required' });
    return;
  }

  const body = await readJson(request);
  const amountCents = Number.parseInt(body.amountCents, 10);
  const requestKey = String(body.requestKey || '');
  if (!Number.isInteger(amountCents) || amountCents < MIN_TRANSFER_CENTS) {
    respond(response, 422, { error: `minimum transfer is ${MIN_TRANSFER_CENTS} cents` });
    return;
  }
  if (!/^[0-9a-f-]{36}$/.test(requestKey)) {
    respond(response, 422, { error: 'requestKey must be a uuid' });
    return;
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const claim = await client.query(
      'INSERT INTO transfer_requests (request_key, rider_id) VALUES ($1, $2) ON CONFLICT (request_key) DO NOTHING RETURNING id',
      [requestKey, actor.id],
    );
    if (claim.rowCount === 0) {
      await client.query('ROLLBACK');
      const existing = await pool.query('SELECT payout_id FROM transfer_requests WHERE request_key = $1', [requestKey]);
      respond(response, 200, { payoutId: existing.rows[0].payout_id, replayed: true });
      return;
    }

    const debit = await client.query(
      `UPDATE wallets SET balance_cents = balance_cents - $1, updated_at = now()
       WHERE rider_id = $2 AND balance_cents >= $1
       RETURNING id, balance_cents, payout_account_id`,
      [amountCents, actor.id],
    );
    if (debit.rowCount === 0) {
      await client.query('ROLLBACK');
      respond(response, 402, { error: 'insufficient balance' });
      return;
    }

    const wallet = debit.rows[0];
    const payout = await payouts.enqueue({
      walletId: wallet.id,
      payoutAccountId: wallet.payout_account_id,
      amountCents,
      client,
    });

    await client.query(
      'INSERT INTO wallet_entries (wallet_id, kind, amount_cents, reference) VALUES ($1, $2, $3, $4)',
      [wallet.id, 'transfer', -amountCents, payout.id],
    );
    await client.query('UPDATE transfer_requests SET payout_id = $1 WHERE request_key = $2', [payout.id, requestKey]);
    await client.query('COMMIT');

    respond(response, 202, { payoutId: payout.id, balanceCents: wallet.balance_cents });
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

const ROUTES = new Map([
  ['POST /api/wallet/transfers', requestTransfer],
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
    console.error('transfer failed', error);
    respond(response, 500, { error: 'internal error' });
  }
});

server.listen(PORT);

module.exports = { server, requestTransfer };
