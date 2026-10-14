import { QueryTypes } from 'sequelize';
import { app, formatCents, resolveMember } from '../lib/slack';
import { sequelize } from '../db/models';

type ReportRow = {
  vendor_name: string;
  requisition_count: number;
  total_cents: number;
};

/** Only these four are sortable, and the value is the column, not the user's text. */
const SORT_COLUMNS: Record<string, string> = {
  spend: 'total_cents',
  count: 'requisition_count',
  vendor: 'vendor_name',
  recent: 'last_raised_at',
};

const MAX_ROWS = 50;

type ReportArgs = { vendorFilter: string; sortKey: string; limit: number };

function parseArgs(text: string): ReportArgs {
  const parts = (text ?? '').trim().split(/\s+/).filter(Boolean);
  const words: string[] = [];
  let sortKey = 'spend';
  let limit = 10;

  for (const part of parts) {
    if (part.startsWith('sort:')) {
      sortKey = part.slice('sort:'.length);
      continue;
    }
    if (part.startsWith('limit:')) {
      limit = Number.parseInt(part.slice('limit:'.length), 10);
      continue;
    }
    words.push(part);
  }

  const safeLimit = Number.isFinite(limit) ? Math.min(Math.max(limit, 1), MAX_ROWS) : 10;
  return { vendorFilter: words.join(' '), sortKey, limit: safeLimit };
}

app.command('/spend-report', async ({ command, ack, respond, logger }) => {
  await ack();

  const member = await resolveMember(command.user_id, command.team_id);
  if (!member) {
    await respond({
      response_type: 'ephemeral',
      text: 'You are not set up in Requisition yet — ask #finance-ops to onboard you.',
    });
    return;
  }

  const { vendorFilter, sortKey, limit } = parseArgs(command.text);
  const orderBy = SORT_COLUMNS[sortKey] ?? SORT_COLUMNS.spend;

  try {
    const rows = await sequelize.query<ReportRow>(
      `select v.name                as vendor_name,
              count(r.id)           as requisition_count,
              sum(r.amount_cents)   as total_cents,
              max(r.created_at)     as last_raised_at
         from requisitions r
         join vendors v on v.id = r.vendor_id
        where r.cost_center_id = :costCenterId
          and r.status in ('approved', 'closed')
          and (:vendorFilter = '' or v.name ilike :vendorPattern)
        group by v.name
        order by ${orderBy} desc
        limit :limit`,
      {
        replacements: {
          costCenterId: member.costCenterId,
          vendorFilter,
          vendorPattern: `%${vendorFilter}%`,
          limit,
        },
        type: QueryTypes.SELECT,
      },
    );

    if (rows.length === 0) {
      await respond({ response_type: 'ephemeral', text: 'No approved spend matches that filter.' });
      return;
    }

    const lines = rows.map(
      (row) => `• *${row.vendor_name}* — ${row.requisition_count} × — ${formatCents(row.total_cents)}`,
    );

    await respond({
      response_type: 'ephemeral',
      text: `Approved spend for your cost centre (sorted by ${sortKey}):\n${lines.join('\n')}`,
    });
  } catch (error) {
    logger.error('spend-report failed', error);
    await respond({ response_type: 'ephemeral', text: 'Could not build the report just now.' });
  }
});
