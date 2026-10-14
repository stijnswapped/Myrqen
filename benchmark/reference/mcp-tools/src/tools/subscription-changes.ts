import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { PutCommand, UpdateCommand } from '@aws-sdk/lib-dynamodb';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { documentClient, tables } from '../config/environment.js';
import { accountScope, requireRole, type ToolContext } from '../auth/sessions.js';

const ACCOUNT_REFERENCE = /^acct_[0-9a-z]{8,32}$/;
const PLAN_CODES = ['starter-monthly', 'growth-monthly', 'growth-annual', 'scale-annual'] as const;

/**
 * Moving an account between plans changes what we bill next cycle, so it is
 * gated the same way the billing console gates it.
 */
export function registerSubscriptionChangeTools(server: McpServer, ctx: ToolContext): void {
  server.registerTool(
    'subscription_plan_change',
    {
      title: 'Change the subscription plan',
      description:
        'Move the account onto a different plan from the next billing cycle. ' +
        'Requires a billing admin session.',
      inputSchema: {
        accountId: z.string().regex(ACCOUNT_REFERENCE),
        planCode: z.enum(PLAN_CODES),
        reason: z.string().min(8).max(400),
        ticketId: z.string().regex(/^TCK-\d{4,8}$/).optional(),
      },
    },
    async ({ accountId, planCode, reason, ticketId }) => {
      const decision = requireRole(ctx, 'billing_admin');
      if (!decision.ok) {
        return {
          content: [{ type: 'text', text: decision.message ?? 'Not allowed.' }],
          isError: true,
        };
      }

      const scope = accountScope(ctx, accountId);
      const updated = await documentClient.send(
        new UpdateCommand({
          TableName: tables.accounts,
          Key: { accountId: scope },
          UpdateExpression: 'SET planCode = :plan, planChangedAt = :now, updatedAt = :now',
          ConditionExpression: 'attribute_exists(accountId)',
          ExpressionAttributeValues: {
            ':plan': planCode,
            ':now': new Date().toISOString(),
          },
          ReturnValues: 'ALL_NEW',
        }),
      );

      await documentClient.send(
        new PutCommand({
          TableName: tables.ticketEvents,
          Item: {
            accountId: scope,
            eventKey: `${ticketId ?? 'no-ticket'}#plan-${randomUUID()}`,
            kind: 'plan_changed',
            actor: ctx.session?.displayName ?? 'local operator',
            createdAt: new Date().toISOString(),
            summary: `Plan set to ${planCode}: ${reason}`,
          },
        }),
      );

      return {
        content: [
          {
            type: 'text',
            text: `${scope} is now on ${String(updated.Attributes?.planCode ?? planCode)}.`,
          },
        ],
      };
    },
  );
}
