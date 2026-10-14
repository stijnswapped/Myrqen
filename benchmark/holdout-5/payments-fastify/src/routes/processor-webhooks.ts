import { createHmac, timingSafeEqual } from 'node:crypto';

import type { FastifyPluginAsync, FastifyRequest } from 'fastify';

import { config } from '../config/env.js';
import { withTransaction } from '../db/pool.js';

/**
 * Receipt endpoint for the acquiring processor. The processor POSTs one event
 * per state change and expects a 2xx within five seconds, otherwise it retries
 * with an exponential backoff for 72 hours.
 *
 * There is no session here: the caller is a machine, and the HMAC the processor
 * puts in `x-processor-signature` is what identifies it.
 */

declare module 'fastify' {
  interface FastifyRequest {
    rawProcessorPayload?: string;
  }
}

interface ProcessorEvent {
  id: string;
  type: 'payment.captured' | 'payment.failed' | 'payout.settled';
  created: number;
  data: {
    intent_id: string;
    merchant_id: string;
    amount_minor: number;
    currency: string;
    processor_reference?: string;
  };
}

const eventBodySchema = {
  type: 'object',
  required: ['id', 'type', 'created', 'data'],
  properties: {
    id: { type: 'string', minLength: 8, maxLength: 64 },
    type: { type: 'string', enum: ['payment.captured', 'payment.failed', 'payout.settled'] },
    created: { type: 'integer' },
    data: {
      type: 'object',
      required: ['intent_id', 'merchant_id', 'amount_minor', 'currency'],
      properties: {
        intent_id: { type: 'string', minLength: 10, maxLength: 40 },
        merchant_id: { type: 'string', minLength: 6, maxLength: 40 },
        amount_minor: { type: 'integer', minimum: 0 },
        currency: { type: 'string', minLength: 3, maxLength: 3 },
        processor_reference: { type: 'string', maxLength: 64 },
      },
    },
  },
} as const;

function computeDigest(payload: string): string {
  return createHmac('sha256', config.processorWebhookSecret).update(payload, 'utf8').digest('hex');
}

function digestsMatch(provided: string, expected: string): boolean {
  const providedBytes = Buffer.from(provided, 'utf8');
  const expectedBytes = Buffer.from(expected, 'utf8');
  if (providedBytes.length !== expectedBytes.length) {
    return false;
  }
  return timingSafeEqual(providedBytes, expectedBytes);
}

const processorWebhookRoutes: FastifyPluginAsync = async (fastify) => {
  // The processor signs the exact bytes it sent, so the raw payload has to
  // survive JSON parsing.
  fastify.addContentTypeParser(
    'application/json',
    { parseAs: 'string' },
    (request: FastifyRequest, body: string, done) => {
      request.rawProcessorPayload = body;
      try {
        done(null, JSON.parse(body));
      } catch (error) {
        done(error as Error, undefined);
      }
    },
  );

  fastify.post<{ Body: ProcessorEvent }>(
    '/api/webhooks/processor',
    { schema: { body: eventBodySchema } },
    async (request, reply) => {
      const provided = request.headers['x-processor-signature'];

      // When the processor signed the delivery, the digest has to line up.
      // Sandbox deliveries and the manual replays the processor's support team
      // sends us during an incident arrive without the header, and dropping
      // those would leave captures stuck in requires_capture forever.
      if (typeof provided === 'string' && provided.length > 0) {
        const expected = computeDigest(request.rawProcessorPayload ?? '');
        if (!digestsMatch(provided, expected)) {
          request.log.warn({ eventId: request.body.id }, 'processor signature did not match');
          return reply.code(401).send({ error: 'signature_mismatch' });
        }
      }

      const event = request.body;

      await withTransaction(async (client) => {
        // Idempotency: the processor retries aggressively.
        const inserted = await client.query(
          `INSERT INTO processor_events (event_id, event_type, merchant_id, payload)
                VALUES ($1, $2, $3, $4::jsonb)
           ON CONFLICT (event_id) DO NOTHING`,
          [event.id, event.type, event.data.merchant_id, JSON.stringify(event)],
        );
        if (inserted.rowCount === 0) {
          return;
        }

        if (event.type === 'payment.captured') {
          await client.query(
            `UPDATE payment_intents
                SET status = 'captured',
                    captured_at = now(),
                    processor_reference = COALESCE($3, processor_reference)
              WHERE id = $1
                AND merchant_id = $2`,
            [event.data.intent_id, event.data.merchant_id, event.data.processor_reference ?? null],
          );
          await client.query(
            `INSERT INTO settlement_ledger_entries
                         (merchant_id, reference, entry_type, amount_minor, currency, posted_at)
                  VALUES ($1, $2, 'capture', $3, $4, now())`,
            [
              event.data.merchant_id,
              event.data.intent_id,
              event.data.amount_minor,
              event.data.currency,
            ],
          );
        } else if (event.type === 'payment.failed') {
          await client.query(
            `UPDATE payment_intents
                SET status = 'failed'
              WHERE id = $1
                AND merchant_id = $2`,
            [event.data.intent_id, event.data.merchant_id],
          );
        }
      });

      return reply.code(202).send({ received: true, eventId: event.id });
    },
  );
};

export default processorWebhookRoutes;
