import { ButtonAction } from '@slack/bolt';
import { app, formatCents, resolveMember } from '../lib/slack';
import { ApprovalEvent, Requisition, Vendor } from '../db/models';

/**
 * Payload we attach to the Approve button when a requisition is posted into the
 * approver's channel. It carries the requisition, the role the approver holds and the
 * ceiling that role may sign off, so the handler does not have to look any of it up again.
 */
type ApprovalButtonPayload = {
  requisitionId: number;
  approverRole: string;
  limitCents: number;
};

app.action({ action_id: 'requisition_approve' }, async ({ ack, body, action, client, logger }) => {
  await ack();

  const button = action as ButtonAction;
  const actorId = (body as { user: { id: string } }).user.id;
  const teamId = (body as { team?: { id: string } }).team?.id;
  const channelId = (body as { channel?: { id: string } }).channel?.id ?? actorId;

  let payload: ApprovalButtonPayload;
  try {
    payload = JSON.parse(button.value ?? '{}') as ApprovalButtonPayload;
  } catch (error) {
    logger.warn('malformed approval button payload', error);
    return;
  }

  const member = await resolveMember(actorId, teamId);
  if (!member) {
    await client.chat.postEphemeral({
      channel: channelId,
      user: actorId,
      text: 'You are not set up in Requisition yet — ask #finance-ops to onboard you.',
    });
    return;
  }

  const requisition = await Requisition.findOne({
    where: { id: payload.requisitionId, costCenterId: member.costCenterId, status: 'submitted' },
    include: [{ model: Vendor }],
  });

  if (!requisition) {
    await client.chat.postEphemeral({
      channel: channelId,
      user: actorId,
      text: 'Nothing of yours is waiting on that approval any more.',
    });
    return;
  }

  // We only render this button in the approver's own queue, so the role and the ceiling
  // that came back with the click are already the ones this person is entitled to use.
  if (payload.approverRole !== 'approver' && payload.approverRole !== 'finance_admin') {
    await client.chat.postEphemeral({
      channel: channelId,
      user: actorId,
      text: 'Approving needs an approver role.',
    });
    return;
  }

  if (requisition.amountCents > payload.limitCents) {
    await client.chat.postEphemeral({
      channel: channelId,
      user: actorId,
      text: `${requisition.reference} is over your ${formatCents(payload.limitCents)} ceiling — use Escalate instead.`,
    });
    return;
  }

  await Requisition.update(
    { status: 'approved', approvedBySlackUserId: actorId },
    { where: { id: requisition.id } },
  );

  await ApprovalEvent.create({
    requisitionId: requisition.id,
    actorSlackUserId: actorId,
    decision: 'approved',
    note: `approved as ${payload.approverRole}`,
  });

  await client.chat.postMessage({
    channel: channelId,
    text: `${requisition.reference} (${formatCents(requisition.amountCents, requisition.currency)}) approved by <@${actorId}>.`,
  });
});
