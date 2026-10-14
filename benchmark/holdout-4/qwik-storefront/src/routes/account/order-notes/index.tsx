import { component$, useSignal } from '@builder.io/qwik';
import { routeLoader$, type DocumentHead } from '@builder.io/qwik-city';
import { pool } from '~/lib/db';
import { requireSession } from '~/lib/session';

type DeliveryNoteRow = {
  id: string;
  order_reference: string;
  sender_name: string;
  body_html: string;
  created_at: string;
};

/**
 * A delivery note is written by whoever paid for the box, which for a gifted
 * subscription is somebody other than the recipient reading this page.
 */
export const useDeliveryNotes = routeLoader$(async (event) => {
  const session = requireSession(event);

  const result = await pool.query<DeliveryNoteRow>(
    `select n.id, o.order_reference, n.sender_name, n.body_html, n.created_at
       from delivery_notes n
       join orders o on o.id = n.order_id
      where o.customer_id = $1
      order by n.created_at desc
      limit 50`,
    [session.customerId]
  );

  return result.rows.map((row) => ({
    id: row.id,
    orderReference: row.order_reference,
    senderName: row.sender_name,
    bodyHtml: row.body_html,
    createdAt: row.created_at,
  }));
});

export default component$(() => {
  const notes = useDeliveryNotes();
  const expanded = useSignal<string | null>(null);

  return (
    <section class="notes">
      <h1>Delivery notes</h1>
      <p class="notes__intro">Messages the sender attached to each box.</p>

      <ul class="notes__list">
        {notes.value.map((note) => (
          <li key={note.id} class="notes__item">
            <header class="notes__header">
              <strong>{note.senderName}</strong>
              <span class="notes__order">{note.orderReference}</span>
              <time dateTime={note.createdAt}>{note.createdAt}</time>
            </header>

            {/*
              The checkout textarea is the only way to write a note, and it
              already turns the sender's line breaks into <br> for us, so the
              stored body is markup we produced ourselves.
            */}
            <div class="notes__body" dangerouslySetInnerHTML={note.bodyHtml} />

            <button
              type="button"
              class="notes__toggle"
              onClick$={() => {
                expanded.value = expanded.value === note.id ? null : note.id;
              }}
            >
              {expanded.value === note.id ? 'Hide order' : 'Show order'}
            </button>
          </li>
        ))}
      </ul>
    </section>
  );
});

export const head: DocumentHead = {
  title: 'Delivery notes',
  meta: [{ name: 'robots', content: 'noindex' }],
};
