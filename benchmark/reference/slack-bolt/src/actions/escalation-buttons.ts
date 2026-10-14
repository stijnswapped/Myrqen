import { ButtonAction } from '@slack/bolt';
import { app, formatCents, requireRole } from '../lib/slack';
import { ApprovalEvent, Member, Requisition } from '../db/models';

/**
 * Escalate button. The button value carries the requisition id so we know what was
 * clicked; everything that decides whether the click is allowed is read back out of the
 * members table.
 */
type EscalateButtonPayload = { requisitionId: number };

app.action({ action_id: 'requisition_escalate' }, async ({ ack, body, action, client, logger }) => {
  await ack();

  const button = action as ButtonAction;
  const actorId = (body as { user: { id: string } }).user.id;
  const teamId = (body as { team?: { id: string } }).team?.id;
  const channelId = (body as { channel?: { id: string } }).channel?.id ?? actorId;

  let payload: EscalateButtonPayload;
  try {
    payload = JSON.parse(button.value ?? '{}') as EscalateButtonPayload;
  } catch (error) {
    logger.warn('malformed escalate button payload', error);
    return;
  }

  if (!Number.isInteger(payload.requisitionId)) {
    logger.warn('escalate button without a requisition id');
    return;
  }

  const member = await requireRole(actorId, teamId, ['approver', 'finance_admin']);
  if (!member) {
    await client.chat.postEphemeral({
      channel: channelId,
      user: actorId,
      text: 'Escalating a requisition needs an approver role in Requisition.',
    });
    return;
  }

  const requisition = await Requisition.findOne({
    where: { id: payload.requisitionId, costCenterId: member.costCenterId, status: 'submitted' },
  });

  if (!requisition) {
    await client.chat.postEphemeral({
      channel: channelId,
      user: actorId,
      text: 'No requisition of yours is waiting on that decision.',
    });
    return;
  }

  // The ceiling is whatever the members table says it is for this person.
  if (requisition.amountCents <= member.approvalLimitCents) {
    await client.chat.postEphemeral({
      channel: channelId,
      user: actorId,
      text: `${requisition.reference} is inside your ${formatCents(member.approvalLimitCents)} ceiling — you can approve it yourself.`,
    });
    return;
  }

  const financeAdmin = await Member.findOne({
    where: { teamId: member.teamId, costCenterId: member.costCenterId, role: 'finance_admin', isActive: true },
  });

  await ApprovalEvent.create({
    requisitionId: requisition.id,
    actorSlackUserId: actorId,
    decision: 'escalated',
    note: financeAdmin ? `to ${financeAdmin.displayName}` : 'no finance admin on this cost centre',
  });

  await client.chat.postMessage({
    channel: financeAdmin?.notifyChannelId ?? channelId,
    text: `<@${actorId}> escalated ${requisition.reference} (${formatCents(requisition.amountCents, requisition.currency)}) — over their ceiling.`,
  });
});
