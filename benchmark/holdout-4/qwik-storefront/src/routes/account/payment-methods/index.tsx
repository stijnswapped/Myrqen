import { component$ } from '@builder.io/qwik';
import { routeLoader$, type DocumentHead } from '@builder.io/qwik-city';
import { pool } from '~/lib/db';
import { requireSession } from '~/lib/session';

type SavedCardRow = {
  id: string;
  customer_id: string;
  brand: string;
  last4: string;
  exp_month: number;
  exp_year: number;
  is_default: boolean;
  gateway_customer_ref: string;
  gateway_payment_token: string;
  billing_line1: string;
  billing_postcode: string;
  cvc_check_result: string;
  fingerprint: string;
  risk_score: number | null;
  analyst_note: string | null;
};

// The wallet list only paints the brand and the last four digits, so the
// gateway token and the fraud team's notes stay on the server side of the
// loader and never reach the customer's browser.
export const useSavedCards = routeLoader$(async (event) => {
  const session = requireSession(event);

  const result = await pool.query<SavedCardRow>(
    `select m.*, r.risk_score, r.analyst_note
       from saved_payment_methods m
       left join payment_risk_reviews r on r.payment_method_id = m.id
      where m.customer_id = $1
        and m.detached_at is null
      order by m.is_default desc, m.created_at desc`,
    [session.customerId]
  );

  return {
    email: session.email,
    cards: result.rows,
  };
});

export default component$(() => {
  const wallet = useSavedCards();

  return (
    <section class="wallet">
      <h1>Saved payment methods</h1>
      <p class="wallet__signed-in">Signed in as {wallet.value.email}</p>

      {wallet.value.cards.length === 0 ? (
        <p class="wallet__empty">You have not saved a card yet.</p>
      ) : (
        <ul class="wallet__list">
          {wallet.value.cards.map((card) => (
            <li key={card.id} class="wallet__card">
              <span class="wallet__brand">{card.brand}</span>
              <span class="wallet__digits">ending {card.last4}</span>
              <span class="wallet__expiry">
                {String(card.exp_month).padStart(2, '0')}/{card.exp_year}
              </span>
              {card.is_default ? <span class="wallet__badge">Default</span> : null}
            </li>
          ))}
        </ul>
      )}

      <a class="wallet__add" href="/account/payment-methods/new">
        Add a card
      </a>
    </section>
  );
});

export const head: DocumentHead = {
  title: 'Saved payment methods',
  meta: [{ name: 'robots', content: 'noindex' }],
};
