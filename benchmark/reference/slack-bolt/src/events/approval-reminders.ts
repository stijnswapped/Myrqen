import { app, formatCents, referenceFrom, resolveMember } from '../lib/slack';
import { Requisition, Vendor } from '../db/models';

/**
 * People chase purchase orders in channel ("any movement on REQ-10432?"). We answer with
 * a one-line status in the thread, and send the commercial detail privately to whoever
 * asked — and only when their cost centre actually owns the requisition.
 */
app.message(/\bREQ-\d{4,8}\b/i, async ({ message, context, client, logger }) => {
  if (message.subtype !== undefined || message.bot_id) return;

  const reference = referenceFrom(message.text ?? '');
  if (!reference) return;

  const member = await resolveMember(message.user, context.teamId);
  if (!member) {
    logger.debug('mention from somebody outside Requisition', { user: message.user });
    return;
  }

  const requisition = await Requisition.findOne({
    where: { reference, costCenterId: member.costCenterId },
    include: [{ model: Vendor }],
  });

  if (!requisition) {
    await client.chat.postEphemeral({
      channel: message.channel,
      user: message.user,
      text: `${reference} is not on your cost centre, so I cannot pull it up for you.`,
    });
    return;
  }

  const vendor = (requisition as Requisition & { vendor?: Vendor }).vendor;

  // Commercial terms go to the person who asked, not to the channel they asked in.
  await client.chat.postEphemeral({
    channel: message.channel,
    user: message.user,
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
          { type: 'mrkdwn', text: `*Vendor*\n${vendor?.name ?? '—'} (tax id ${vendor?.taxId ?? '—'})` },
          { type: 'mrkdwn', text: `*Remittance*\n${vendor?.contactEmail ?? '—'} · acct ••••${vendor?.bankAccountLast4 ?? '????'}` },
          { type: 'mrkdwn', text: `*Negotiated rate*\n${formatCents(vendor?.negotiatedRateCents ?? 0)}` },
          { type: 'mrkdwn', text: `*Raised by*\n<@${requisition.requesterSlackUserId}>` },
        ],
      },
    ],
  });

  await client.chat.postMessage({
    channel: message.channel,
    thread_ts: message.ts,
    text: `${reference} is *${requisition.status}* — details sent to you privately.`,
  });
});
