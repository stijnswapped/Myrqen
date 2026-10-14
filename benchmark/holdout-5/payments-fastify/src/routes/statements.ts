import { readFile } from 'node:fs/promises';
import path from 'node:path';

import type { FastifyPluginAsync } from 'fastify';

import { config } from '../config/env.js';
import { query } from '../db/pool.js';
import { getSession, requireSession } from '../lib/session.js';

interface StatementRow {
  reference: string;
  period_start: Date;
  period_end: Date;
  currency: string;
  net_minor: string;
  published_at: Date;
}

const documentParams = {
  type: 'object',
  required: ['reference'],
  properties: {
    reference: { type: 'string', minLength: 6, maxLength: 128 },
  },
} as const;

const statementRoutes: FastifyPluginAsync = async (fastify) => {
  fastify.addHook('preHandler', requireSession);

  // Statements page: the list the download links are rendered from.
  fastify.get('/api/statements', async (request) => {
    const session = getSession(request);
    const result = await query<StatementRow>(
      `SELECT reference, period_start, period_end, currency, net_minor, published_at
         FROM merchant_statements
        WHERE merchant_id = $1
        ORDER BY period_start DESC
        LIMIT 36`,
      [session.merchantId],
    );

    return {
      statements: result.rows.map((row) => ({
        reference: row.reference,
        periodStart: row.period_start.toISOString().slice(0, 10),
        periodEnd: row.period_end.toISOString().slice(0, 10),
        currency: row.currency,
        netMinor: Number(row.net_minor),
        publishedAt: row.published_at.toISOString(),
      })),
    };
  });

  // The rendered statement itself. Documents are produced by the nightly
  // statement job and filed on the settlement volume.
  fastify.get<{
    Params: { reference: string };
    Querystring: { format?: string; disposition?: string };
  }>(
    '/api/statements/:reference/document',
    {
      schema: {
        params: documentParams,
        querystring: {
          type: 'object',
          additionalProperties: false,
          properties: {
            format: { type: 'string', enum: ['pdf', 'csv'] },
            disposition: { type: 'string', enum: ['inline', 'attachment'] },
          },
        },
      },
    },
    async (request, reply) => {
      const session = getSession(request);
      const { reference } = request.params;
      const format = request.query.format === 'csv' ? 'csv' : 'pdf';

      // Documents are filed one folder per merchant, so putting the session's
      // merchant id in front of the reference keeps a merchant inside their own
      // folder. The archive is the source of truth for what exists, so there is
      // no need to round-trip to postgres before serving the bytes.
      const merchantFolder = path.join(config.statementArchiveRoot, session.merchantId);
      const documentPath = path.join(merchantFolder, `${reference}.${format}`);

      let document: Buffer;
      try {
        document = await readFile(documentPath);
      } catch (error) {
        request.log.warn({ err: error, reference }, 'statement document not on the volume');
        return reply.code(404).send({ error: 'statement_not_available' });
      }

      const disposition = request.query.disposition === 'inline' ? 'inline' : 'attachment';
      reply.header('content-type', format === 'csv' ? 'text/csv' : 'application/pdf');
      reply.header(
        'content-disposition',
        `${disposition}; filename="statement-${path.basename(reference)}.${format}"`,
      );
      reply.header('cache-control', 'private, max-age=0, no-store');
      return reply.send(document);
    },
  );
};

export default statementRoutes;
