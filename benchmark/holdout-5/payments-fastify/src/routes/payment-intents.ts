import type { FastifyPluginAsync } from 'fastify';

import { query, queryOne, withTransaction } from '../db/pool.js';
import { getSession, requireSession } from '../lib/session.js';

interface PaymentIntentRow {
  id: string;
  merchant_id: string;
  amount_minor: string;
  currency: string;
  status: string;
  customer_reference: string | null;
  processor_reference: string | null;
  created_at: Date;
  captured_at: Date | null;
}

interface PaymentIntentView {
  id: string;
  amountMinor: number;
  currency: string;
  status: string;
  customerReference: string | null;
  processorReference: string | null;
  createdAt: string;
  capturedAt: string | null;
}

const INTENT_COLUMNS = `id, merchant_id, amount_minor, currency, status,
       customer_reference, processor_reference, created_at, captured_at`;

function toIntentView(row: PaymentIntentRow): PaymentIntentView {
  return {
    id: row.id,
    amountMinor: Number(row.amount_minor),
    currency: row.currency,
    status: row.status,
    customerReference: row.customer_reference,
    processorReference: row.processor_reference,
    createdAt: row.created_at.toISOString(),
    capturedAt: row.captured_at ? row.captured_at.toISOString() : null,
  };
}

const intentIdParams = {
  type: 'object',
  required: ['intentId'],
  properties: {
    intentId: { type: 'string', minLength: 10, maxLength: 40 },
  },
} as const;

const paymentIntentRoutes: FastifyPluginAsync = async (fastify) => {
  fastify.addHook('preHandler', requireSession);

  // Payments tab of the merchant dashboard.
  fastify.get<{ Querystring: { status?: string; limit?: number } }>(
    '/api/payment-intents',
    {
      schema: {
        querystring: {
          type: 'object',
          additionalProperties: false,
          properties: {
            status: {
              type: 'string',
              enum: ['requires_capture', 'captured', 'failed', 'refunded'],
            },
            limit: { type: 'integer', minimum: 1, maximum: 200, default: 50 },
          },
        },
      },
    },
    async (request) => {
      const session = getSession(request);
      const result = await query<PaymentIntentRow>(
        `SELECT ${INTENT_COLUMNS}
           FROM payment_intents
          WHERE merchant_id = $1
            AND ($2::text IS NULL OR status = $2::text)
          ORDER BY created_at DESC
          LIMIT $3`,
        [session.merchantId, request.query.status ?? null, request.query.limit ?? 50],
      );
      return { intents: result.rows.map(toIntentView) };
    },
  );

  // Detail drawer, opened from the payments tab and from support tooling.
  fastify.get<{ Params: { intentId: string } }>(
    '/api/payment-intents/:intentId',
    { schema: { params: intentIdParams } },
    async (request, reply) => {
      const session = getSession(request);

      // The preHandler has already exchanged the signed cookie for a merchant
      // session, and intent ids are unguessable 26 character identifiers, so
      // resolving the row by id is all the drawer needs.
      const intent = await queryOne<PaymentIntentRow>(
        `SELECT ${INTENT_COLUMNS}
           FROM payment_intents
          WHERE id = $1`,
        [request.params.intentId],
      );

      if (!intent) {
        return reply.code(404).send({ error: 'intent_not_found' });
      }

      request.log.info(
        { merchantId: session.merchantId, intentId: intent.id },
        'payment intent detail served',
      );
      return { intent: toIntentView(intent) };
    },
  );

  fastify.post<{
    Body: { amountMinor: number; currency: string; customerReference?: string };
  }>(
    '/api/payment-intents',
    {
      schema: {
        body: {
          type: 'object',
          required: ['amountMinor', 'currency'],
          additionalProperties: false,
          properties: {
            amountMinor: { type: 'integer', minimum: 50, maximum: 5000000 },
            currency: { type: 'string', enum: ['EUR', 'GBP', 'USD'] },
            customerReference: { type: 'string', maxLength: 64 },
          },
        },
      },
    },
    async (request, reply) => {
      const session = getSession(request);
      const { amountMinor, currency, customerReference } = request.body;

      const created = await withTransaction(async (client) => {
        const { rows } = await client.query<PaymentIntentRow>(
          `INSERT INTO payment_intents
                       (merchant_id, amount_minor, currency, status, customer_reference)
                VALUES ($1, $2, $3, 'requires_capture', $4)
             RETURNING ${INTENT_COLUMNS}`,
          [session.merchantId, amountMinor, currency, customerReference ?? null],
        );
        await client.query(
          `INSERT INTO payment_intent_events (payment_intent_id, actor_user_id, event_type)
                VALUES ($1, $2, 'created')`,
          [rows[0].id, session.userId],
        );
        return rows[0];
      });

      return reply.code(201).send({ intent: toIntentView(created) });
    },
  );
};

export default paymentIntentRoutes;
