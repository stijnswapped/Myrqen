import type { FastifyPluginAsync } from 'fastify';

import { query } from '../db/pool.js';
import { getSession, requireSession } from '../lib/session.js';

interface LedgerEntryRow {
  entry_id: string;
  reference: string;
  entry_type: string;
  amount_minor: string;
  currency: string;
  posted_at: Date;
}

/**
 * The export grid offers the same sorting affordance as the settlements grid,
 * but the column the client asks for is only ever a key into this map. The SQL
 * fragment that ends up in the statement is one we wrote, never one we were
 * handed.
 */
const SORTABLE_LEDGER_COLUMNS: Readonly<Record<string, string>> = Object.freeze({
  posted_at: 'e.posted_at',
  amount: 'e.amount_minor',
  reference: 'e.reference',
  entry_type: 'e.entry_type',
});

const exportQuerySchema = {
  type: 'object',
  additionalProperties: false,
  properties: {
    sort: { type: 'string', minLength: 1, maxLength: 64 },
    direction: { type: 'string', maxLength: 4 },
    limit: { type: 'integer', minimum: 1, maximum: 1000, default: 250 },
    offset: { type: 'integer', minimum: 0, default: 0 },
  },
} as const;

function toEntryView(row: LedgerEntryRow) {
  return {
    entryId: row.entry_id,
    reference: row.reference,
    entryType: row.entry_type,
    amountMinor: Number(row.amount_minor),
    currency: row.currency,
    postedAt: row.posted_at.toISOString(),
  };
}

const ledgerExportRoutes: FastifyPluginAsync = async (fastify) => {
  fastify.addHook('preHandler', requireSession);

  fastify.get<{
    Querystring: { sort?: string; direction?: string; limit?: number; offset?: number };
  }>(
    '/api/ledger-exports',
    { schema: { querystring: exportQuerySchema } },
    async (request, reply) => {
      const session = getSession(request);
      const { limit = 250, offset = 0 } = request.query;
      const sortKey = request.query.sort ?? 'posted_at';

      const column = Object.prototype.hasOwnProperty.call(SORTABLE_LEDGER_COLUMNS, sortKey)
        ? SORTABLE_LEDGER_COLUMNS[sortKey]
        : undefined;

      if (!column) {
        return reply.code(400).send({
          error: 'unsupported_sort',
          supported: Object.keys(SORTABLE_LEDGER_COLUMNS),
        });
      }

      const direction = request.query.direction === 'asc' ? 'ASC' : 'DESC';

      const result = await query<LedgerEntryRow>(
        `SELECT e.entry_id, e.reference, e.entry_type, e.amount_minor, e.currency, e.posted_at
           FROM settlement_ledger_entries e
          WHERE e.merchant_id = $1
          ORDER BY ${column} ${direction}
          LIMIT $2
         OFFSET $3`,
        [session.merchantId, limit, offset],
      );

      return {
        sort: sortKey,
        direction: direction.toLowerCase(),
        entries: result.rows.map(toEntryView),
      };
    },
  );
};

export default ledgerExportRoutes;
