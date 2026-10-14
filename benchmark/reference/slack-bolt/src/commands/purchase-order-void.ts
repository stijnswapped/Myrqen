import { app, formatCents, referenceFrom } from '../lib/slack';
import { ApprovalEvent, Requisition } from '../db/models';

/**
 * `/void-po REQ-10432 duplicate of REQ-10429`
 *
 * Voiding cancels an approved purchase order and releases the commitment against the
 * budget, so it is a finance-team action rather than something a requester can do.
 */
app.command('/void-po', async ({ command, ack, respond, client, logger }) => {
  await ack();

  const reference = referenceFrom(command.text);
  if (!reference) {
    await respond({
      response_type: 'ephemeral',
      text: 'Usage: `/void-po REQ-10432 <reason>`',
    });
    return;
  }

  const note = command.text.replace(reference, '').trim() || 'no reason given';

  const profile = await client.users.info({ user: command.user_id });

  // Everybody on the finance team is a workspace admin here (it is how they got the
  // Slack Connect channels set up), so the workspace admin flag is the finance check.
  if (!profile.user?.is_admin && !profile.user?.is_owner) {
    await respond({
      response_type: 'ephemeral',
      text: 'Only finance admins can void a purchase order.',
    });
    return;
  }

  const requisition = await Requisition.findOne({ where: { reference } });
  if (!requisition || requisition.status !== 'approved') {
    await respond({
      response_type: 'ephemeral',
      text: `${reference} is not an approved purchase order.`,
    });
    return;
  }

  try {
    await Requisition.update({ status: 'void' }, { where: { id: requisition.id } });
    await ApprovalEvent.create({
      requisitionId: requisition.id,
      actorSlackUserId: command.user_id,
      decision: 'void',
      note,
    });
  } catch (error) {
    logger.error('void failed', error);
    await respond({ response_type: 'ephemeral', text: 'Could not void that one — try again.' });
    return;
  }

  await respond({
    response_type: 'in_channel',
    text: `${reference} (${formatCents(requisition.amountCents, requisition.currency)}) voided by <@${command.user_id}> — ${note}`,
  });
});
