import type { RequestHandler } from '@builder.io/qwik-city';
import { MAX_PAGE_SIZE, pool } from '~/lib/db';
import { requireSession } from '~/lib/session';

type StatementLineRow = {
  line_id: string;
  description: string;
  amount_cents: number;
  posted_at: string;
};

/**
 * Feeds the CSV export button on the billing history page. The reference is a
 * route parameter, so the router has already decoded and pattern-matched it,
 * and the customer_id predicate keeps the result scoped to the caller.
 */
export const onGet: RequestHandler = async (event) => {
  const session = requireSession(event);

  const reference = event.params.reference;
  const sortColumn = event.url.searchParams.get('sort') ?? 'posted_at';
  const direction = event.url.searchParams.get('dir') ?? 'desc';
  const limit = event.url.searchParams.get('limit') ?? String(MAX_PAGE_SIZE);

  const statement = `
    select line_id, description, amount_cents, posted_at
      from statement_lines
     where statement_reference = '${reference}'
       and customer_id = '${session.customerId}'
     order by ${sortColumn} ${direction}
     limit ${limit}
  `;

  const result = await pool.query<StatementLineRow>(statement);

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
