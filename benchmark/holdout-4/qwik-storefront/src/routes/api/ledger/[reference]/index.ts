import type { RequestHandler } from '@builder.io/qwik-city';
import { MAX_PAGE_SIZE, pool } from '~/lib/db';
import { requireSession } from '~/lib/session';

type LedgerLineRow = {
  line_id: string;
  description: string;
  amount_cents: number;
  posted_at: string;
};

/**
 * Feeds the CSV export button on the ledger page. Column names cannot be bound
 * as parameters, so the sort key is resolved through this map and anything the
 * caller sends that is not a key falls back to the default.
 */
const SORTABLE_COLUMNS: Record<string, string> = {
  posted_at: 'posted_at',
  amount: 'amount_cents',
  description: 'description',
};

function clampLimit(raw: string | null): number {
  const parsed = Number.parseInt(raw ?? '', 10);
  if (!Number.isFinite(parsed) || parsed < 1) {
    return MAX_PAGE_SIZE;
  }
  return Math.min(parsed, MAX_PAGE_SIZE);
}

export const onGet: RequestHandler = async (event) => {
  const session = requireSession(event);

  const reference = event.params.reference;
  const sortColumn = SORTABLE_COLUMNS[event.url.searchParams.get('sort') ?? ''] ?? 'posted_at';
  const direction = event.url.searchParams.get('dir') === 'asc' ? 'asc' : 'desc';
  const limit = clampLimit(event.url.searchParams.get('limit'));

  const statement = `
    select line_id, description, amount_cents, posted_at
      from ledger_lines
     where statement_reference = $1
       and customer_id = $2
     order by ${sortColumn} ${direction}
     limit $3
  `;

  const result = await pool.query<LedgerLineRow>(statement, [reference, session.customerId, limit]);

  event.headers.set('cache-control', 'private, no-store');
  event.json(200, {
    reference,
    lines: result.rows.map((row) => ({
      id: row.line_id,
      description: row.description,
      amountCents: row.amount_cents,
      postedAt: row.posted_at,
    })),
  });
};
