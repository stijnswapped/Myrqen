import { app, formatCents, referenceFrom, requireRole } from '../lib/slack';
import { ApprovalEvent, Requisition } from '../db/models';

/**
 * `/close-po REQ-10432 goods received`
 *
 * Closing settles an approved purchase order once the invoice is matched. Same finance
 * gate as voiding, taken from the role we hold for this person in the members table —
 * their Slack workspace permissions are somebody else's concern.
 */
app.command('/close-po', async ({ command, ack, respond, logger }) => {
  await ack();

  const reference = referenceFrom(command.text);
  if (!reference) {
    await respond({
      response_type: 'ephemeral',
      text: 'Usage: `/close-po REQ-10432 <note>`',
    });
    return;
  }

  const note = command.text.replace(reference, '').trim() || 'no note';

  const member = await requireRole(command.user_id, command.team_id, ['finance_admin']);
  if (!member) {
    await respond({
      response_type: 'ephemeral',
      text: 'Closing a purchase order needs the finance admin role in Requisition.',
    });
    return;
  }

  const requisition = await Requisition.findOne({
    where: { reference, costCenterId: member.costCenterId, status: 'approved' },
  });

  if (!requisition) {
    await respond({
      response_type: 'ephemeral',
      text: `${reference} is not an approved purchase order on your cost centre.`,
    });
    return;
  }

  try {
    await Requisition.update({ status: 'closed' }, { where: { id: requisition.id } });
    await ApprovalEvent.create({
      requisitionId: requisition.id,
      actorSlackUserId: command.user_id,
      decision: 'closed',
      note,
    });
  } catch (error) {
    logger.error('close failed', error);
    await respond({ response_type: 'ephemeral', text: 'Could not close that one — try again.' });
    return;
  }

  await respond({
    response_type: 'in_channel',
    text: `${reference} (${formatCents(requisition.amountCents, requisition.currency)}) closed by <@${command.user_id}> — ${note}`,
  });
});
