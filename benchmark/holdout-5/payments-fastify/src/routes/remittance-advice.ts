import { readFile } from 'node:fs/promises';
import path from 'node:path';

import type { FastifyPluginAsync } from 'fastify';

import { config } from '../config/env.js';
import { queryOne } from '../db/pool.js';
import { getSession, requireSession } from '../lib/session.js';

/**
 * Remittance advices are the per-payout breakdown a merchant hands to their
 * accountant. References are minted by the payout runner and always look like
 * RA-20260731-4KQ7ZP.
 */
const REMITTANCE_REFERENCE = /^RA-[0-9]{8}-[A-Z0-9]{6}$/;

const remittanceAdviceRoutes: FastifyPluginAsync = async (fastify) => {
  fastify.addHook('preHandler', requireSession);

  fastify.get<{ Params: { reference: string }; Querystring: { disposition?: string } }>(
    '/api/remittance-advice/:reference/document',
    {
      schema: {
        params: {
          type: 'object',
          required: ['reference'],
          properties: { reference: { type: 'string', minLength: 18, maxLength: 18 } },
        },
        querystring: {
          type: 'object',
          additionalProperties: false,
          properties: { disposition: { type: 'string', enum: ['inline', 'attachment'] } },
        },
      },
    },
    async (request, reply) => {
      const session = getSession(request);
      const { reference } = request.params;

      if (!REMITTANCE_REFERENCE.test(reference)) {
        return reply.code(400).send({ error: 'malformed_reference' });
      }

      // The advice has to exist for this merchant before we go near the volume.
      const advice = await queryOne<{ reference: string; payout_id: string }>(
        `SELECT reference, payout_id
           FROM remittance_advices
          WHERE reference = $1
            AND merchant_id = $2`,
        [reference, session.merchantId],
      );
      if (!advice) {
        return reply.code(404).send({ error: 'remittance_advice_not_found' });
      }

      const merchantRoot = path.resolve(config.remittanceArchiveRoot, session.merchantId);
      const documentPath = path.resolve(merchantRoot, `${reference}.pdf`);

      // Belt and braces. The pattern check above already rules out separators,
      // but the resolved path still has to live under this merchant's folder
      // before we are willing to read it.
      if (!documentPath.startsWith(`${merchantRoot}${path.sep}`)) {
        return reply.code(400).send({ error: 'malformed_reference' });
      }

      let document: Buffer;
      try {
        document = await readFile(documentPath);
      } catch (error) {
        request.log.warn({ err: error, reference }, 'remittance advice not on the volume');
        return reply.code(404).send({ error: 'remittance_advice_not_available' });
      }

      const disposition = request.query.disposition === 'inline' ? 'inline' : 'attachment';
      reply.header('content-type', 'application/pdf');
      reply.header('content-disposition', `${disposition}; filename="${reference}.pdf"`);
      reply.header('cache-control', 'private, max-age=0, no-store');
      return reply.send(document);
    },
  );
};

export default remittanceAdviceRoutes;
