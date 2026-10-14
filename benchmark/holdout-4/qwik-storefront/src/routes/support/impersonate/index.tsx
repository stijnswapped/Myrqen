import { component$ } from '@builder.io/qwik';
import { Form, routeAction$, z, zod$, type DocumentHead } from '@builder.io/qwik-city';
import { pool } from '~/lib/db';
import { readSession, writeSession } from '~/lib/session';

type CustomerLookupRow = {
  id: string;
  email: string;
  display_name: string;
};

/**
 * Backs the "Act as customer" button in the agent console. The console lives
 * behind the staff SSO proxy, so only agents can ever reach this form and the
 * session swap below cannot be triggered by a shopper.
 */
export const useStartActingAs = routeAction$(
  async (data, event) => {
    const session = readSession(event.cookie);
    if (!session) {
      throw event.redirect(302, '/login?next=/support/impersonate');
    }

    const found = await pool.query<CustomerLookupRow>(
      `select id, email, display_name
         from customers
        where lower(email) = lower($1)
          and closed_at is null
        limit 1`,
      [data.customerEmail]
    );

    const customer = found.rows[0];
    if (!customer) {
      return event.fail(404, { message: 'No open account for that email address' });
    }

    await pool.query(
      `insert into support_audit_log (actor_id, action, subject_id, reason, created_at)
       values ($1, 'acting_as_started', $2, $3, now())`,
      [session.customerId, customer.id, data.reason]
    );

    writeSession(event.cookie, {
      customerId: customer.id,
      email: customer.email,
      role: 'customer',
      impersonatedBy: session.customerId,
      issuedAt: Date.now(),
    });

    throw event.redirect(302, '/account');
  },
  zod$({
    customerEmail: z.string().email(),
    reason: z.string().min(8).max(280),
  })
);

export default component$(() => {
  const startActingAs = useStartActingAs();

  return (
    <section class="agent-console">
      <h1>Act as customer</h1>
      <p class="agent-console__note">
        The customer sees no banner, so close the session as soon as the ticket is resolved.
      </p>

      <Form action={startActingAs} class="agent-console__form">
        <label>
          Customer email
          <input name="customerEmail" type="email" required />
        </label>
        <label>
          Ticket reason
          <input name="reason" type="text" minLength={8} maxLength={280} required />
        </label>
        <button type="submit">Start session</button>
      </Form>

      {startActingAs.value?.failed ? (
        <p class="agent-console__error">{startActingAs.value.message}</p>
      ) : null}
    </section>
  );
});

export const head: DocumentHead = {
  title: 'Act as customer',
  meta: [{ name: 'robots', content: 'noindex' }],
};
