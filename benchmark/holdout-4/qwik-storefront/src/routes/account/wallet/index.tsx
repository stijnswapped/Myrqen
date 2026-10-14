import { component$ } from '@builder.io/qwik';
import { routeLoader$, type DocumentHead } from '@builder.io/qwik-city';
import { pool } from '~/lib/db';
import { requireSession } from '~/lib/session';

type WalletRow = {
  id: string;
  brand: string;
  last4: string;
  exp_month: number;
  exp_year: number;
  is_default: boolean;
};

export type WalletEntry = {
  id: string;
  brand: string;
  last4: string;
  expiry: string;
  isDefault: boolean;
};

// Everything this loader returns is serialised into the SSR payload, so the
// statement lists the display columns by hand and the rows are mapped into a
// view model before they leave the server.
export const useWalletSummary = routeLoader$(async (event) => {
  const session = requireSession(event);

  const result = await pool.query<WalletRow>(
    `select m.id, m.brand, m.last4, m.exp_month, m.exp_year, m.is_default
       from saved_payment_methods m
      where m.customer_id = $1
        and m.detached_at is null
      order by m.is_default desc, m.created_at desc`,
    [session.customerId]
  );

  const cards: WalletEntry[] = result.rows.map((row) => ({
    id: row.id,
    brand: row.brand,
    last4: row.last4,
    expiry: `${String(row.exp_month).padStart(2, '0')}/${row.exp_year}`,
    isDefault: row.is_default,
  }));

  return {
    email: session.email,
    cards,
  };
});

export default component$(() => {
  const wallet = useWalletSummary();

  return (
    <section class="wallet">
      <h1>Wallet</h1>
      <p class="wallet__signed-in">Signed in as {wallet.value.email}</p>

      {wallet.value.cards.length === 0 ? (
        <p class="wallet__empty">You have not saved a card yet.</p>
      ) : (
        <ul class="wallet__list">
          {wallet.value.cards.map((card) => (
            <li key={card.id} class="wallet__card">
              <span class="wallet__brand">{card.brand}</span>
              <span class="wallet__digits">ending {card.last4}</span>
              <span class="wallet__expiry">{card.expiry}</span>
              {card.isDefault ? <span class="wallet__badge">Default</span> : null}
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
  title: 'Wallet',
  meta: [{ name: 'robots', content: 'noindex' }],
};
