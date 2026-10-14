import type { FastifyPluginAsync } from 'fastify';

import { query, queryOne, withTransaction } from '../db/pool.js';
import { getSession, requireSession } from '../lib/session.js';

interface RefundRow {
  id: string;
  merchant_id: string;
  payment_intent_id: string;
  amount_minor: string;
  currency: string;
  status: string;
  reason: string | null;
  created_at: Date;
}

const REFUND_COLUMNS = `id, merchant_id, payment_intent_id, amount_minor,
       currency, status, reason, created_at`;

function toRefundView(row: RefundRow) {
  return {
    id: row.id,
    paymentIntentId: row.payment_intent_id,
    amountMinor: Number(row.amount_minor),
    currency: row.currency,
    status: row.status,
    reason: row.reason,
    createdAt: row.created_at.toISOString(),
  };
}

const refundRoutes: FastifyPluginAsync = async (fastify) => {
  fastify.addHook('preHandler', requireSession);

  fastify.get<{ Querystring: { paymentIntentId?: string; limit?: number } }>(
    '/api/refunds',
    {
      schema: {
        querystring: {
          type: 'object',
          additionalProperties: false,
          properties: {
            paymentIntentId: { type: 'string', minLength: 10, maxLength: 40 },
            limit: { type: 'integer', minimum: 1, maximum: 200, default: 50 },
          },
        },
      },
    },
    async (request) => {
      const session = getSession(request);
      const result = await query<RefundRow>(
        `SELECT ${REFUND_COLUMNS}
           FROM refunds
          WHERE merchant_id = $1
            AND ($2::text IS NULL OR payment_intent_id = $2::text)
          ORDER BY created_at DESC
          LIMIT $3`,
        [session.merchantId, request.query.paymentIntentId ?? null, request.query.limit ?? 50],
      );
      return { refunds: result.rows.map(toRefundView) };
    },
  );

  fastify.get<{ Params: { refundId: string } }>(
    '/api/refunds/:refundId',
    {
      schema: {
        params: {
          type: 'object',
          required: ['refundId'],
          properties: { refundId: { type: 'string', minLength: 10, maxLength: 40 } },
        },
      },
    },
    async (request, reply) => {
      const session = getSession(request);

      // Ownership is part of the predicate rather than a check we have to
      // remember to run afterwards: a refund id belonging to another merchant
      // does not resolve, and the caller cannot tell that it exists.
      const refund = await queryOne<RefundRow>(
        `SELECT ${REFUND_COLUMNS}
           FROM refunds
          WHERE id = $1
            AND merchant_id = $2`,
        [request.params.refundId, session.merchantId],
      );

      if (!refund) {
        return reply.code(404).send({ error: 'refund_not_found' });
      }
      return { refund: toRefundView(refund) };
    },
  );

  fastify.post<{
    Body: { paymentIntentId: string; amountMinor: number; reason?: string };
  }>(
    '/api/refunds',
    {
      schema: {
        body: {
          type: 'object',
          required: ['paymentIntentId', 'amountMinor'],
          additionalProperties: false,
          properties: {
            paymentIntentId: { type: 'string', minLength: 10, maxLength: 40 },
            amountMinor: { type: 'integer', minimum: 1, maximum: 5000000 },
            reason: { type: 'string', maxLength: 140 },
          },
        },
      },
    },
    async (request, reply) => {
      const session = getSession(request);
      const { paymentIntentId, amountMinor, reason } = request.body;

      return withTransaction(async (client) => {
        const { rows: intents } = await client.query<{
          id: string;
          amount_minor: string;
          currency: string;
          status: string;
        }>(
          `SELECT id, amount_minor, currency, status
             FROM payment_intents
            WHERE id = $1
              AND merchant_id = $2
              FOR UPDATE`,
          [paymentIntentId, session.merchantId],
        );

        const intent = intents[0];
        if (!intent) {
          return reply.code(404).send({ error: 'intent_not_found' });
        }
        if (intent.status !== 'captured') {
          return reply.code(409).send({ error: 'intent_not_captured', status: intent.status });
        }

        const { rows: totals } = await client.query<{ refunded_minor: string }>(
          `SELECT COALESCE(SUM(amount_minor), 0) AS refunded_minor
             FROM refunds
            WHERE payment_intent_id = $1
              AND status <> 'failed'`,
          [intent.id],
        );

        const remainingMinor = Number(intent.amount_minor) - Number(totals[0].refunded_minor);
        if (amountMinor > remainingMinor) {
          return reply.code(422).send({ error: 'refund_exceeds_remaining', remainingMinor });
        }

        const { rows } = await client.query<RefundRow>(
          `INSERT INTO refunds
                       (merchant_id, payment_intent_id, amount_minor, currency, status, reason, requested_by)
                VALUES ($1, $2, $3, $4, 'pending', $5, $6)
             RETURNING ${REFUND_COLUMNS}`,
          [
            session.merchantId,
            intent.id,
            amountMinor,
            intent.currency,
            reason ?? null,
            session.userId,
          ],
        );

        return reply.code(201).send({ refund: toRefundView(rows[0]) });
      });
    },
  );
};

export default refundRoutes;
