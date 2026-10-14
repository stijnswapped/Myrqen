import { server$ } from '@builder.io/qwik-city';
import { pool } from './db';
import { readSession } from './session';

export type ThreadMessage = {
  id: string;
  threadId: string;
  authorName: string;
  body: string;
  sentAt: string;
};

type ThreadMessageRow = {
  id: string;
  thread_id: string;
  author_name: string;
  body: string;
  sent_at: string;
};

const PAGE_SIZE = 25;

/** Badge count in the header. */
export const countOpenRefundThreads = server$(async function () {
  const session = readSession(this.cookie);
  if (!session) {
    return 0;
  }

  const result = await pool.query<{ open_count: string }>(
    `select count(*)::text as open_count
       from refund_threads
      where customer_id = $1
        and status = 'open'`,
    [session.customerId]
  );

  return Number(result.rows[0]?.open_count ?? 0);
});

/**
 * Backs the "Show earlier replies" button on a refund thread. A server function
 * is a plain POST endpoint, so the thread is re-scoped to the cookie session
 * here rather than trusting the id the browser sent.
 */
export const loadEarlierRefundMessages = server$(async function (
  threadId: string,
  before: string
): Promise<ThreadMessage[]> {
  const session = readSession(this.cookie);
  if (!session) {
    throw new Error('Sign in to continue');
  }

  const result = await pool.query<ThreadMessageRow>(
    `select m.id, m.thread_id, m.author_name, m.body, m.sent_at
       from refund_thread_messages m
       join refund_threads t on t.id = m.thread_id
      where m.thread_id = $1
        and t.customer_id = $2
        and m.sent_at < $3
      order by m.sent_at desc
      limit ${PAGE_SIZE}`,
    [threadId, session.customerId, before]
  );

  return result.rows
    .map((row) => ({
      id: row.id,
      threadId: row.thread_id,
      authorName: row.author_name,
      body: row.body,
      sentAt: row.sent_at,
    }))
    .reverse();
});
