import { app, formatCents, referenceFrom } from '../lib/slack';
import { CostCenter, Requisition, Vendor } from '../db/models';

/**
 * "@requisition REQ-10432" anywhere the bot can see posts the full commercial picture for
 * that purchase order back into the conversation, which saves finance being pinged for it.
 */
app.event('app_mention', async ({ event, client, say, logger }) => {
  const reference = referenceFrom(event.text ?? '');
  if (!reference) {
    await say('Mention me with a reference — `@requisition REQ-10432` — and I will pull it up.');
    return;
  }

  const requisition = await Requisition.findOne({
    where: { reference },
    include: [{ model: Vendor }, { model: CostCenter }],
  });

  if (!requisition) {
    await say(`I have nothing on file for ${reference}.`);
    return;
  }

  const vendor = (requisition as Requisition & { vendor?: Vendor }).vendor;
  const costCenter = (requisition as Requisition & { costCenter?: CostCenter }).costCenter;

  logger.info('digest requested', { reference, by: event.user, channel: event.channel });

  // The bot is only in channels somebody deliberately invited it to, so anyone who can
  // see this message is already cleared for the vendor terms.
  await client.chat.postMessage({
    channel: event.channel,
    thread_ts: event.ts,
    text: `${reference} — ${requisition.status}`,
    blocks: [
      {
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `*${reference}* — ${requisition.status} — ${formatCents(requisition.amountCents, requisition.currency)}`,
        },
      },
      {
        type: 'section',
        fields: [
          { type: 'mrkdwn', text: `*Cost centre*\n${costCenter?.code ?? '—'} (owner <@${costCenter?.ownerSlackUserId}>)` },
          { type: 'mrkdwn', text: `*Raised by*\n<@${requisition.requesterSlackUserId}>` },
          { type: 'mrkdwn', text: `*Vendor*\n${vendor?.name ?? '—'} (tax id ${vendor?.taxId ?? '—'})` },
          { type: 'mrkdwn', text: `*Remittance*\n${vendor?.contactEmail ?? '—'} · acct ••••${vendor?.bankAccountLast4 ?? '????'}` },
          { type: 'mrkdwn', text: `*Negotiated rate*\n${formatCents(vendor?.negotiatedRateCents ?? 0)}` },
          {
            type: 'mrkdwn',
            text: `*Contract price*\n${
              requisition.contractPriceCents === null
                ? 'not set'
                : formatCents(requisition.contractPriceCents, requisition.currency)
            }`,
          },
        ],
      },
      {
        type: 'context',
        elements: [{ type: 'mrkdwn', text: `Justification: ${requisition.justification || '—'}` }],
      },
    ],
  });
});
