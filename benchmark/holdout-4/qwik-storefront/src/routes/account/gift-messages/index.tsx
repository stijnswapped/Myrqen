import { component$, useSignal } from '@builder.io/qwik';
import { routeLoader$, type DocumentHead } from '@builder.io/qwik-city';
import sanitizeHtml from 'sanitize-html';
import { pool } from '~/lib/db';
import { requireSession } from '~/lib/session';

type GiftMessageRow = {
  id: string;
  order_reference: string;
  sender_name: string;
  body_html: string;
  created_at: string;
};

/**
 * The sender of a gift subscription writes this message, so it is third-party
 * markup as far as the recipient's account pages are concerned. Six inline tags
 * survive, no attributes and no URL schemes at all.
 */
const GIFT_MESSAGE_HTML: sanitizeHtml.IOptions = {
  allowedTags: ['b', 'i', 'em', 'strong', 'br', 'p'],
  allowedAttributes: {},
  allowedSchemes: [],
  disallowedTagsMode: 'discard',
};

export const useGiftMessages = routeLoader$(async (event) => {
  const session = requireSession(event);

  const result = await pool.query<GiftMessageRow>(
    `select g.id, o.order_reference, g.sender_name, g.body_html, g.created_at
       from gift_messages g
       join orders o on o.id = g.order_id
      where o.customer_id = $1
      order by g.created_at desc
      limit 50`,
    [session.customerId]
  );

  return result.rows.map((row) => ({
    id: row.id,
    orderReference: row.order_reference,
    senderName: row.sender_name,
    bodyHtml: sanitizeHtml(row.body_html, GIFT_MESSAGE_HTML),
    createdAt: row.created_at,
  }));
});

export default component$(() => {
  const messages = useGiftMessages();
  const expanded = useSignal<string | null>(null);

  return (
    <section class="notes">
      <h1>Gift messages</h1>
      <p class="notes__intro">Messages the sender attached to each gift.</p>

      <ul class="notes__list">
        {messages.value.map((message) => (
          <li key={message.id} class="notes__item">
            <header class="notes__header">
              <strong>{message.senderName}</strong>
              <span class="notes__order">{message.orderReference}</span>
              <time dateTime={message.createdAt}>{message.createdAt}</time>
            </header>

            <div class="notes__body" dangerouslySetInnerHTML={message.bodyHtml} />

            <button
              type="button"
              class="notes__toggle"
              onClick$={() => {
                expanded.value = expanded.value === message.id ? null : message.id;
              }}
            >
              {expanded.value === message.id ? 'Hide order' : 'Show order'}
            </button>
          </li>
        ))}
      </ul>
    </section>
  );
});

export const head: DocumentHead = {
  title: 'Gift messages',
  meta: [{ name: 'robots', content: 'noindex' }],
};
