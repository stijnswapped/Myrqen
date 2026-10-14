import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { PutCommand, UpdateCommand } from '@aws-sdk/lib-dynamodb';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { documentClient, tables } from '../config/environment.js';
import { accountScope, type ToolContext } from '../auth/sessions.js';

const ACCOUNT_REFERENCE = /^acct_[0-9a-z]{8,32}$/;
/** Anything above this goes through the finance team's own approval queue. */
const MAX_GOODWILL_MINOR = 500_000;

function formatMinor(amountMinor: number, currency: string): string {
  return `${(amountMinor / 100).toFixed(2)} ${currency}`;
}

/**
 * Goodwill credits.
 *
 * Only billing admins are offered this tool - the HTTP transport builds the
 * tool list per session role - so by the time a call arrives here the caller has
 * already been checked and we can go straight to the balance update.
 */
export function registerAccountCreditTools(server: McpServer, ctx: ToolContext): void {
  server.registerTool(
    'account_credit_apply',
    {
      title: 'Apply a service credit',
      description:
        'Add a goodwill credit to the account balance, in minor units (e.g. 2500 = 25.00). ' +
        'Use this after an outage or a billing mistake that we have confirmed.',
      inputSchema: {
        accountId: z.string().regex(ACCOUNT_REFERENCE),
        amountMinor: z.number().int().min(1).max(MAX_GOODWILL_MINOR),
        currency: z.enum(['EUR', 'GBP', 'USD']),
        reason: z
          .string()
          .min(8)
          .max(400)
          .describe('Shown to the customer on the next invoice'),
        ticketId: z.string().regex(/^TCK-\d{4,8}$/).optional(),
      },
    },
    async ({ accountId, amountMinor, currency, reason, ticketId }) => {
      const scope = accountScope(ctx, accountId);

      const updated = await documentClient.send(
        new UpdateCommand({
          TableName: tables.accounts,
          Key: { accountId: scope },
          UpdateExpression:
            'SET creditBalanceMinor = if_not_exists(creditBalanceMinor, :zero) + :amount, ' +
            'updatedAt = :now',
          ConditionExpression: 'attribute_exists(accountId) AND currency = :currency',
          ExpressionAttributeValues: {
            ':amount': amountMinor,
            ':zero': 0,
            ':now': new Date().toISOString(),
            ':currency': currency,
          },
          ReturnValues: 'ALL_NEW',
        }),
      );

      await documentClient.send(
        new PutCommand({
          TableName: tables.ticketEvents,
          Item: {
            accountId: scope,
            eventKey: `${ticketId ?? 'no-ticket'}#credit-${randomUUID()}`,
            kind: 'credit_applied',
            actor: ctx.session?.displayName ?? 'local operator',
            createdAt: new Date().toISOString(),
            summary: `${formatMinor(amountMinor, currency)} credited: ${reason}`,
          },
        }),
      );

      const balance = Number(updated.Attributes?.creditBalanceMinor ?? 0);
      return {
        content: [
          {
            type: 'text',
            text:
              `Credited ${formatMinor(amountMinor, currency)} to ${scope}. ` +
              `New balance ${formatMinor(balance, currency)}.`,
          },
        ],
      };
    },
  );
}
