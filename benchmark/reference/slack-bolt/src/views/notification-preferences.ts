import { ViewStateValue } from '@slack/bolt';
import { app } from '../lib/slack';
import { Member } from '../db/models';

/**
 * "Notification settings" modal. Same block-per-column layout as the profile modal, but
 * the columns a submission may touch are listed here rather than taken from the payload.
 */
const EDITABLE_COLUMNS = ['digestHour', 'timezone', 'notifyChannelId'] as const;

type EditableColumn = (typeof EDITABLE_COLUMNS)[number];

function isEditableColumn(candidate: string): candidate is EditableColumn {
  return (EDITABLE_COLUMNS as readonly string[]).includes(candidate);
}

function firstValue(action: ViewStateValue): string | null {
  if (typeof action.value === 'string' && action.value.length > 0) return action.value;
  if (action.selected_option?.value) return action.selected_option.value;
  if (action.selected_conversation) return action.selected_conversation;
  return null;
}

app.view('notification_preferences_submit', async ({ ack, body, view, client, logger }) => {
  const patch: Partial<Record<EditableColumn, string | number>> = {};

  for (const [blockId, block] of Object.entries(view.state.values)) {
    if (!isEditableColumn(blockId)) {
      // A submission can name any block it likes; anything that is not one of ours is
      // not a column we are willing to write.
      logger.debug('ignoring unknown preference block', { blockId });
      continue;
    }

    for (const action of Object.values(block)) {
      const value = firstValue(action as ViewStateValue);
      if (value === null) continue;

      if (blockId === 'digestHour') {
        const hour = Number.parseInt(value, 10);
        if (!Number.isInteger(hour) || hour < 0 || hour > 23) {
          await ack({
            response_action: 'errors',
            errors: { digestHour: 'Pick an hour between 0 and 23.' },
          });
          return;
        }
        patch.digestHour = hour;
        continue;
      }

      patch[blockId] = value;
    }
  }

  await ack();

  if (Object.keys(patch).length === 0) {
    return;
  }

  try {
    await Member.update(patch, {
      where: { slackUserId: body.user.id, teamId: body.team?.id },
    });
  } catch (error) {
    logger.error('preference update failed', error);
    return;
  }

  await client.chat.postMessage({
    channel: body.user.id,
    text: `Notification settings saved: ${Object.keys(patch).join(', ')}.`,
  });
});
