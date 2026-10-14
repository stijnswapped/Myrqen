import type { FastifyPluginAsync } from 'fastify';

import { withTransaction } from '../db/pool.js';
import { requireRole, requireSession, type MerchantRole } from '../lib/session.js';

/**
 * Treasury controls sit next to the payout schedule in the dashboard but are
 * gated separately: an analyst can look at a payout, only the merchant owner
 * and the treasury administrators may move money around.
 */
const TREASURY_ROLES: readonly MerchantRole[] = ['owner', 'treasury_admin'];

interface PayoutRow {
  id: string;
  merchant_id: string;
  amount_minor: string;
  currency: string;
  status: string;
  review_state: string;
}

const payoutIdParams = {
  type: 'object',
  required: ['payoutId'],
  properties: { payoutId: { type: 'string', minLength: 10, maxLength: 40 } },
} as const;

const treasuryControlRoutes: FastifyPluginAsync = async (fastify) => {
  fastify.addHook('preHandler', requireSession);

  fastify.post<{ Params: { payoutId: string }; Body: { reason: string } }>(
    '/api/treasury/payouts/:payoutId/hold',
    {
      schema: {
        params: payoutIdParams,
        body: {
          type: 'object',
          required: ['reason'],
          additionalProperties: false,
          properties: { reason: { type: 'string', minLength: 3, maxLength: 280 } },
        },
      },
    },
    async (request, reply) => {
      // requireRole answers 403 itself, so an undefined session means the reply
      // has already been sent and this handler is done.
      const session = requireRole(request, reply, TREASURY_ROLES);
      if (!session) {
        return reply;
      }

      return withTransaction(async (client) => {
        const { rows } = await client.query<PayoutRow>(
          `SELECT id, merchant_id, amount_minor, currency, status, review_state
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
        if (payout.status !== 'scheduled') {
          return reply.code(409).send({ error: 'payout_not_holdable', status: payout.status });
        }

        await client.query(
          `UPDATE payout_schedules
              SET status = 'on_hold',
                  review_state = 'manual_review',
                  held_by = $2,
                  held_at = now(),
                  hold_reason = $3
            WHERE id = $1`,
          [payout.id, session.userId, request.body.reason],
        );

        await client.query(
          `INSERT INTO payout_release_audit (payout_id, actor_user_id, actor_role, note)
                VALUES ($1, $2, $3, $4)`,
          [payout.id, session.userId, session.role, `hold: ${request.body.reason}`],
        );

        return { payoutId: payout.id, status: 'on_hold' };
      });
    },
  );
};

export default treasuryControlRoutes;
