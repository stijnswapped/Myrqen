import { component$ } from '@builder.io/qwik';
import { Form, routeAction$, z, zod$, type DocumentHead } from '@builder.io/qwik-city';
import { pool } from '~/lib/db';
import { isSupportAgent, readSession, writeSession } from '~/lib/session';

type HandoverTargetRow = {
  customer_id: string;
  email: string;
  ticket_id: string;
};

/**
 * Backs the "Take over session" button on a ticket. The action re-checks the
 * caller's role and the ticket assignment on the server, because a route action
 * is just a POST endpoint that anybody can call directly.
 */
export const useStartHandover = routeAction$(
  async (data, event) => {
    const session = readSession(event.cookie);
    if (!session) {
      throw event.redirect(302, '/login?next=/support/handover');
    }

    if (!isSupportAgent(session)) {
      return event.fail(403, { message: 'Only support agents can take over a session' });
    }

    const found = await pool.query<HandoverTargetRow>(
      `select c.id as customer_id, c.email, t.id as ticket_id
         from support_tickets t
         join customers c on c.id = t.customer_id
        where t.id = $1
          and t.assigned_agent_id = $2
          and t.status = 'open'
          and c.closed_at is null
        limit 1`,
      [data.ticketId, session.customerId]
    );

    const target = found.rows[0];
    if (!target) {
      return event.fail(403, { message: 'That ticket is not assigned to you' });
    }

    await pool.query(
      `insert into support_audit_log (actor_id, action, subject_id, reason, created_at)
       values ($1, 'handover_started', $2, $3, now())`,
      [session.customerId, target.customer_id, data.reason]
    );

    writeSession(event.cookie, {
      customerId: target.customer_id,
      email: target.email,
      role: 'customer',
      impersonatedBy: session.customerId,
      issuedAt: Date.now(),
    });

    throw event.redirect(302, '/account');
  },
  zod$({
    ticketId: z.string().uuid(),
    reason: z.string().min(8).max(280),
  })
);

export default component$(() => {
  const startHandover = useStartHandover();

  return (
    <section class="agent-console">
      <h1>Take over session</h1>
      <p class="agent-console__note">
        Only tickets assigned to you appear here. Every handover is written to the audit log.
      </p>

      <Form action={startHandover} class="agent-console__form">
        <label>
          Ticket id
          <input name="ticketId" type="text" required />
        </label>
        <label>
          Handover reason
          <input name="reason" type="text" minLength={8} maxLength={280} required />
        </label>
        <button type="submit">Take over</button>
      </Form>

      {startHandover.value?.failed ? (
        <p class="agent-console__error">{startHandover.value.message}</p>
      ) : null}
    </section>
  );
});

export const head: DocumentHead = {
  title: 'Take over session',
  meta: [{ name: 'robots', content: 'noindex' }],
};
