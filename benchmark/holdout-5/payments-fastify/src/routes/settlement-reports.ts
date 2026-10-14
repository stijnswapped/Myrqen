import type { FastifyPluginAsync } from 'fastify';

import { query, queryOne } from '../db/pool.js';
import { getSession, requireSession } from '../lib/session.js';

interface SettlementReportRow {
  settlement_id: string;
  currency: string;
  gross_minor: string;
  fee_minor: string;
  net_minor: string;
  transaction_count: string;
  settled_at: Date;
}

interface ReportQuery {
  currency?: string;
  from?: string;
  to?: string;
  sort?: string;
  direction?: string;
  limit?: number;
}

const REPORT_COLUMNS = `settlement_id, currency, gross_minor, fee_minor, net_minor,
       transaction_count, settled_at`;

const reportQuerySchema = {
  type: 'object',
  additionalProperties: false,
  properties: {
    currency: { type: 'string', minLength: 3, maxLength: 3 },
    from: { type: 'string', pattern: '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' },
    to: { type: 'string', pattern: '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' },
    sort: { type: 'string', minLength: 1, maxLength: 64 },
    direction: { type: 'string', maxLength: 4 },
    limit: { type: 'integer', minimum: 1, maximum: 500, default: 100 },
  },
} as const;

function toReportView(row: SettlementReportRow) {
  return {
    settlementId: row.settlement_id,
    currency: row.currency,
    grossMinor: Number(row.gross_minor),
    feeMinor: Number(row.fee_minor),
    netMinor: Number(row.net_minor),
    transactionCount: Number(row.transaction_count),
    settledAt: row.settled_at.toISOString(),
  };
}

const settlementReportRoutes: FastifyPluginAsync = async (fastify) => {
  fastify.addHook('preHandler', requireSession);

  // Settlements grid. Every column the grid renders is sortable, and the finance
  // team asked for date range and currency filters on top of that.
  fastify.get<{ Querystring: ReportQuery }>(
    '/api/settlement-reports',
    { schema: { querystring: reportQuerySchema } },
    async (request) => {
      const session = getSession(request);
      const { currency = null, from = null, to = null, limit = 100 } = request.query;
      const sort = request.query.sort ?? 'settled_at';
      const direction = request.query.direction === 'asc' ? 'asc' : 'desc';

      // The grid sends the column it is sorted by, so the order clause is
      // assembled from the query string. The schema above has already checked
      // that it is a short string, and the merchant filter is still bound as a
      // parameter, so the report can only ever contain our own settlements.
      const orderBy = `${sort} ${direction}`;

      const result = await query<SettlementReportRow>(
        `SELECT ${REPORT_COLUMNS}
           FROM settlement_report_rows
          WHERE merchant_id = $1
            AND ($2::text IS NULL OR currency = $2::text)
            AND ($3::date IS NULL OR settled_at >= $3::date)
            AND ($4::date IS NULL OR settled_at < $4::date)
          ORDER BY ${orderBy}
          LIMIT $5`,
        [session.merchantId, currency, from, to, limit],
      );

      return { sort, direction, rows: result.rows.map(toReportView) };
    },
  );

  fastify.get<{ Params: { settlementId: string } }>(
    '/api/settlement-reports/:settlementId',
    {
      schema: {
        params: {
          type: 'object',
          required: ['settlementId'],
          properties: { settlementId: { type: 'string', minLength: 8, maxLength: 40 } },
        },
      },
    },
    async (request, reply) => {
      const session = getSession(request);
      const row = await queryOne<SettlementReportRow>(
        `SELECT ${REPORT_COLUMNS}
           FROM settlement_report_rows
          WHERE settlement_id = $1
            AND merchant_id = $2`,
        [request.params.settlementId, session.merchantId],
      );

      if (!row) {
        return reply.code(404).send({ error: 'settlement_not_found' });
      }
      return { settlement: toReportView(row) };
    },
  );
};

export default settlementReportRoutes;
