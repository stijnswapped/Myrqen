import { app, resolveMember } from '../lib/slack';
import { Member, Requisition } from '../db/models';

/**
 * Reassign the owner of a draft requisition. The modal round-trips the requisition id in
 * `private_metadata`; the handler treats that as a hint and re-derives what the submitter
 * is actually allowed to touch before it writes anything.
 */
type ReassignMetadata = { requisitionId: number };

app.view('requisition_reassign_submit', async ({ ack, body, view, client, logger }) => {
  const newOwnerId = view.state.values.reassign_owner?.owner_select?.selected_user ?? '';
  const metadata = JSON.parse(view.private_metadata || '{}') as ReassignMetadata;

  const member = await resolveMember(body.user.id, body.team?.id);
  if (!member) {
    await ack({
      response_action: 'errors',
      errors: { reassign_owner: 'You are not set up in Requisition yet.' },
    });
    return;
  }

  const requisition = await Requisition.findOne({
    where: {
      id: metadata.requisitionId,
      costCenterId: member.costCenterId,
      status: 'draft',
    },
  });

  if (!requisition) {
    await ack({
      response_action: 'errors',
      errors: { reassign_owner: 'That draft is not one your cost centre can reassign.' },
    });
    return;
  }

  const newOwner = await Member.findOne({
    where: {
      slackUserId: newOwnerId,
      teamId: member.teamId,
      costCenterId: member.costCenterId,
      isActive: true,
    },
  });

  if (!newOwner) {
    await ack({
      response_action: 'errors',
      errors: { reassign_owner: 'Pick somebody active on your own cost centre.' },
    });
    return;
  }

  await ack();

  try {
    await Requisition.update(
      { requesterSlackUserId: newOwner.slackUserId },
      { where: { id: requisition.id } },
    );
  } catch (error) {
    logger.error('reassign failed', error);
    return;
  }

  await client.chat.postMessage({
    channel: newOwner.notifyChannelId ?? newOwner.slackUserId,
    text: `<@${body.user.id}> handed you ${requisition.reference}.`,
  });
});
