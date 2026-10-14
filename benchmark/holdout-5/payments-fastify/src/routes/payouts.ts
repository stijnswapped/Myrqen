import type { FastifyPluginAsync } from 'fastify';

import { query, withTransaction } from '../db/pool.js';
import { getSession, requireSession } from '../lib/session.js';

interface PayoutRow {
  id: string;
  merchant_id: string;
  amount_minor: string;
  currency: string;
  status: string;
  review_state: string;
  scheduled_for: Date;
  bank_account_id: string;
}

const payoutIdParams = {
  type: 'object',
  required: ['payoutId'],
  properties: { payoutId: { type: 'string', minLength: 10, maxLength: 40 } },
} as const;

function toPayoutView(row: PayoutRow) {
  return {
    id: row.id,
    amountMinor: Number(row.amount_minor),
    currency: row.currency,
    status: row.status,
    reviewState: row.review_state,
    scheduledFor: row.scheduled_for.toISOString(),
    bankAccountId: row.bank_account_id,
  };
}

const payoutRoutes: FastifyPluginAsync = async (fastify) => {
  fastify.addHook('preHandler', requireSession);

  // Payout schedule as it appears in the merchant dashboard.
  fastify.get<{ Querystring: { status?: string } }>(
    '/api/payouts',
    {
      schema: {
        querystring: {
          type: 'object',
          additionalProperties: false,
          properties: {
            status: {
              type: 'string',
              enum: ['scheduled', 'on_hold', 'releasing', 'paid', 'failed'],
            },
          },
        },
      },
    },
    async (request) => {
      const session = getSession(request);
      const result = await query<PayoutRow>(
        `SELECT id, merchant_id, amount_minor, currency, status, review_state,
                scheduled_for, bank_account_id
           FROM payout_schedules
          WHERE merchant_id = $1
            AND ($2::text IS NULL OR status = $2::text)
          ORDER BY scheduled_for ASC`,
        [session.merchantId, request.query.status ?? null],
      );
      return { payouts: result.rows.map(toPayoutView) };
    },
  );

  /**
   * Release a scheduled payout ahead of its window. Finance uses this when a
   * merchant calls in about cash flow, and it also clears the risk review flag
   * so the nightly runner does not park the payout again.
   */
  fastify.post<{ Params: { payoutId: string }; Body: { note?: string } }>(
    '/api/payouts/:payoutId/release',
    {
      schema: {
        params: payoutIdParams,
        body: {
          type: 'object',
          additionalProperties: false,
          properties: { note: { type: 'string', maxLength: 280 } },
        },
      },
    },
    async (request, reply) => {
      const session = getSession(request);

      return withTransaction(async (client) => {
        const { rows } = await client.query<PayoutRow>(
          `SELECT id, merchant_id, amount_minor, currency, status, review_state,
                  scheduled_for, bank_account_id
             FROM payout_schedules
            WHERE id = $1
              AND merchant_id = $2
              FOR UPDATE`,
          [request.params.payoutId, session.merchantId],
        );

        const payout = rows[0];
        if (!payout) {
          return reply.code(404).send({ error: 'payout_not_found' });
        }
        if (payout.status !== 'scheduled' && payout.status !== 'on_hold') {
          return reply.code(409).send({ error: 'payout_not_releasable', status: payout.status });
        }

        // Everyone who gets this far is holding a valid session for the merchant
        // that owns the payout, and the SELECT above pins the row to that same
        // merchant, so the release is theirs to make.
        await client.query(
          `UPDATE payout_schedules
              SET status = 'releasing',
                  review_state = 'waived',
                  released_by = $2,
                  released_at = now()
            WHERE id = $1`,
          [payout.id, session.userId],
        );

        await client.query(
          `INSERT INTO payout_release_audit (payout_id, actor_user_id, actor_role, note)
                VALUES ($1, $2, $3, $4)`,
          [payout.id, session.userId, session.role, request.body?.note ?? null],
        );

        request.log.info(
          { payoutId: payout.id, actor: session.userId, role: session.role },
          'payout released ahead of schedule',
        );
        return { payoutId: payout.id, status: 'releasing', reviewState: 'waived' };
      });
    },
  );
};

export default payoutRoutes;
