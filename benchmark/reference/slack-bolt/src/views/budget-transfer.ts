import { app, formatCents } from '../lib/slack';
import { Budget, sequelize } from '../db/models';

/**
 * Budget transfer modal, opened from the `/budget` overflow menu. When we open it we
 * stash the budget the person was looking at in `private_metadata`, and the modal itself
 * only asks for the target budget and the amount.
 */
type TransferMetadata = { sourceBudgetId: number; fiscalPeriod: string };

app.view('budget_transfer_submit', async ({ ack, body, view, client, logger }) => {
  const values = view.state.values;
  const rawAmount = values.transfer_amount?.amount_input?.value ?? '';
  const targetBudgetId = Number(values.transfer_target?.target_select?.selected_option?.value);
  const amountCents = Math.round(Number.parseFloat(rawAmount.replace(/[, ]/g, '')) * 100);

  if (!Number.isFinite(amountCents) || amountCents <= 0) {
    await ack({
      response_action: 'errors',
      errors: { transfer_amount: 'Enter an amount greater than zero.' },
    });
    return;
  }

  // private_metadata is ours: we wrote it when we opened the modal and Slack signs the
  // payload it comes back in, so the source budget here is the one we put there.
  const metadata = JSON.parse(view.private_metadata || '{}') as TransferMetadata;

  const source = await Budget.findByPk(metadata.sourceBudgetId);
  const target = await Budget.findByPk(targetBudgetId);

  if (!source || !target) {
    await ack({
      response_action: 'errors',
      errors: { transfer_target: 'That budget line no longer exists.' },
    });
    return;
  }

  const available = source.allocatedCents - source.committedCents;
  if (amountCents > available) {
    await ack({
      response_action: 'errors',
      errors: { transfer_amount: `Only ${formatCents(available)} is uncommitted on that line.` },
    });
    return;
  }

  await ack();

  try {
    await sequelize.transaction(async (transaction) => {
      await Budget.update(
        { allocatedCents: source.allocatedCents - amountCents },
        { where: { id: source.id }, transaction },
      );
      await Budget.update(
        { allocatedCents: target.allocatedCents + amountCents },
        { where: { id: target.id }, transaction },
      );
    });
  } catch (error) {
    logger.error('budget transfer failed', error);
    return;
  }

  await client.chat.postMessage({
    channel: body.user.id,
    text: `Moved ${formatCents(amountCents)} from budget #${source.id} to #${target.id} for ${metadata.fiscalPeriod}.`,
  });
});
