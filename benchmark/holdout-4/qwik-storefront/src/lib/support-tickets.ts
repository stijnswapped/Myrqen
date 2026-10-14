import { server$ } from '@builder.io/qwik-city';
import { pool } from './db';
import { readSession } from './session';

export type TicketMessage = {
  id: string;
  ticketId: string;
  authorName: string;
  body: string;
  sentAt: string;
};

type TicketMessageRow = {
  id: string;
  ticket_id: string;
  author_name: string;
  body: string;
  sent_at: string;
};

const PAGE_SIZE = 25;

/** Badge count in the header. */
export const countOpenTickets = server$(async function () {
  const session = readSession(this.cookie);
  if (!session) {
    return 0;
  }

  const result = await pool.query<{ open_count: string }>(
    `select count(*)::text as open_count
       from support_tickets
      where customer_id = $1
        and status = 'open'`,
    [session.customerId]
  );

  return Number(result.rows[0]?.open_count ?? 0);
});

/**
 * Backs the "Show earlier replies" button on a ticket thread. The thread page
 * has already loaded the newest ten messages through its route loader, so this
 * only pages further back into a thread the customer is looking at anyway.
 */
export const loadEarlierTicketMessages = server$(async function (
  ticketId: string,
  before: string
): Promise<TicketMessage[]> {
  const session = readSession(this.cookie);
  if (!session) {
    throw new Error('Sign in to continue');
  }

  const result = await pool.query<TicketMessageRow>(
    `select m.id, m.ticket_id, m.author_name, m.body, m.sent_at
       from support_ticket_messages m
      where m.ticket_id = $1
        and m.sent_at < $2
      order by m.sent_at desc
      limit ${PAGE_SIZE}`,
    [ticketId, before]
  );

  return result.rows
    .map((row) => ({
      id: row.id,
      ticketId: row.ticket_id,
      authorName: row.author_name,
      body: row.body,
      sentAt: row.sent_at,
    }))
    .reverse();
});
