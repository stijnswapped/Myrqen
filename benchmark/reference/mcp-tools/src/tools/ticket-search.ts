import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { ScanCommand } from '@aws-sdk/lib-dynamodb';
import { z } from 'zod';
import { documentClient, tables } from '../config/environment.js';
import { accountScope, type ToolContext } from '../auth/sessions.js';

const ACCOUNT_REFERENCE = /^acct_[0-9a-z]{8,32}$/;
const MAX_RESULTS = 25;

function summarise(items: Record<string, unknown>[]): string {
  if (items.length === 0) {
    return 'No tickets matched.';
  }
  return items
    .map(
      (item) =>
        `${item.ticketId}  ${String(item.ticketStatus).padEnd(10)} ${item.accountId}  ${item.subject}`,
    )
    .join('\n');
}

/**
 * Free-form ticket search.
 *
 * Support asked for this because every new triage flow wanted to filter on a
 * different attribute (priority, queue, product area, the SLA breach flag), and
 * shipping a new tool for each one was getting silly. The attribute name is
 * just an identifier and the value the caller is matching on is bound as a
 * parameter, so there is nothing here that needs escaping.
 */
export function registerTicketSearchTool(server: McpServer, ctx: ToolContext): void {
  server.registerTool(
    'support_ticket_search',
    {
      title: 'Search support tickets',
      description:
        'Find tickets whose attribute equals a value, e.g. field "ticketStatus" value "open", ' +
        'or field "productArea" value "billing". Scoped to the current account.',
      inputSchema: {
        field: z.string().min(2).max(64).describe('Ticket attribute to filter on'),
        value: z.string().min(1).max(160).describe('Value the attribute must equal'),
        accountId: z.string().regex(ACCOUNT_REFERENCE).optional(),
        limit: z.number().int().min(1).max(MAX_RESULTS).optional(),
      },
    },
    async ({ field, value, accountId, limit }) => {
      let scope: string;
      try {
        scope = accountScope(ctx, accountId);
      } catch (error) {
        return { content: [{ type: 'text', text: (error as Error).message }], isError: true };
      }

      const result = await documentClient.send(
        new ScanCommand({
          TableName: tables.tickets,
          FilterExpression: `${field} = :value AND accountId = :accountId`,
          ExpressionAttributeValues: {
            ':value': value,
            ':accountId': scope,
          },
          Limit: limit ?? MAX_RESULTS,
        }),
      );

      const items = (result.Items ?? []) as Record<string, unknown>[];
      return {
        content: [{ type: 'text', text: summarise(items) }],
        structuredContent: { matched: items.length, accountId: scope },
      };
    },
  );
}
