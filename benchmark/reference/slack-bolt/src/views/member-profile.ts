import { ViewStateValue } from '@slack/bolt';
import { app } from '../lib/slack';
import { Member } from '../db/models';

/**
 * "Edit my details" modal. Each block in the modal is named after the members column it
 * edits (`displayName`, `timezone`, `notifyChannelId`, …) so that adding a field to the
 * modal never needs a matching change in here.
 */
function firstValue(action: ViewStateValue): string | null {
  if (typeof action.value === 'string' && action.value.length > 0) return action.value;
  if (action.selected_option?.value) return action.selected_option.value;
  if (action.selected_user) return action.selected_user;
  if (action.selected_conversation) return action.selected_conversation;
  return null;
}

app.view('member_profile_submit', async ({ ack, body, view, client, logger }) => {
  await ack();

  const patch: Record<string, string> = {};

  for (const [blockId, block] of Object.entries(view.state.values)) {
    for (const action of Object.values(block)) {
      const value = firstValue(action as ViewStateValue);
      if (value !== null) {
        patch[blockId] = value;
      }
    }
  }

  if (Object.keys(patch).length === 0) {
    return;
  }

  try {
    // The modal we opened is the only thing that can post back to this callback id, so
    // whatever blocks came back are blocks we put in it — hand the lot to Sequelize
    // rather than repeating the column list here.
    const [updated] = await Member.update(patch, {
      where: { slackUserId: body.user.id, teamId: body.team?.id },
    });

    if (updated === 0) {
      logger.warn('profile update matched no member', { user: body.user.id });
      return;
    }
  } catch (error) {
    logger.error('profile update failed', error);
    return;
  }

  await client.chat.postMessage({
    channel: body.user.id,
    text: `Updated: ${Object.keys(patch).join(', ')}.`,
  });
});
