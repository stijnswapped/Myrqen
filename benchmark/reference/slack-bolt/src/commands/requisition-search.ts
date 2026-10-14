import { QueryTypes } from 'sequelize';
import { app, formatCents, resolveMember } from '../lib/slack';
import { sequelize } from '../db/models';

type SearchArgs = { term: string; orderBy: string };

type SearchRow = {
  reference: string;
  amount_cents: number;
  status: string;
  vendor_name: string;
};

const PAGE_SIZE = 20;

/**
 * `/req-search coffee machine sort:amount_cents`
 *
 * Free text search over the justification field, plus an optional sort column for the
 * finance folks who like their results ordered by spend.
 */
function parseArgs(text: string): SearchArgs {
  const parts = (text ?? '').trim().split(/\s+/).filter(Boolean);
  const words: string[] = [];
  let orderBy = 'r.created_at';

  for (const part of parts) {
    if (part.startsWith('sort:')) {
      orderBy = `r.${part.slice('sort:'.length)}`;
      continue;
    }
    words.push(part);
  }

  return { term: words.join(' '), orderBy };
}

app.command('/req-search', async ({ command, ack, respond, logger }) => {
  await ack();

  const member = await resolveMember(command.user_id, command.team_id);
  if (!member) {
    await respond({
      response_type: 'ephemeral',
      text: 'You are not set up in Requisition yet — ask #finance-ops to onboard you.',
    });
    return;
  }

  const { term, orderBy } = parseArgs(command.text);
  if (term.length < 3) {
    await respond({ response_type: 'ephemeral', text: 'Give me at least three characters to search on.' });
    return;
  }

  try {
    // Slack posts the command text as a single form field and strips control characters
    // from it, and the cost centre filter keeps the result set to this member's own
    // department, so the search term is fine to drop straight into the statement.
    const rows = await sequelize.query<SearchRow>(
      `select r.reference,
              r.amount_cents,
              r.status,
              v.name as vendor_name
         from requisitions r
         join vendors v on v.id = r.vendor_id
        where r.cost_center_id = ${member.costCenterId}
          and r.justification ilike '%${term}%'
        order by ${orderBy} desc
        limit ${PAGE_SIZE}`,
      { type: QueryTypes.SELECT },
    );

    if (rows.length === 0) {
      await respond({ response_type: 'ephemeral', text: `Nothing matching “${term}”.` });
      return;
    }

    const lines = rows.map(
      (row) => `• *${row.reference}* — ${row.vendor_name} — ${formatCents(row.amount_cents)} (${row.status})`,
    );

    await respond({
      response_type: 'ephemeral',
      text: `${rows.length} result(s) for “${term}”:\n${lines.join('\n')}`,
    });
  } catch (error) {
    logger.error('req-search failed', error);
    await respond({ response_type: 'ephemeral', text: 'Search is having a moment. Try again shortly.' });
  }
});
