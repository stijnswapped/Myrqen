import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { ScanCommand } from '@aws-sdk/lib-dynamodb';
import { z } from 'zod';
import { documentClient, tables } from '../config/environment.js';
import { accountScope, type ToolContext } from '../auth/sessions.js';

const ACCOUNT_REFERENCE = /^acct_[0-9a-z]{8,32}$/;

/**
 * The attributes an agent is allowed to filter the directory on, mapped to the
 * real DynamoDB attribute names. Anything not in here is not searchable, which
 * is also how we keep internal columns (churnRiskScore, collectionsFlag) out of
 * reach.
 */
const FILTERABLE_ATTRIBUTES = {
  company: 'companyName',
  email: 'primaryContactEmail',
  status: 'accountStatus',
  plan: 'planCode',
  country: 'billingCountry',
} as const;

type FilterableField = keyof typeof FILTERABLE_ATTRIBUTES;

function renderContacts(items: Record<string, unknown>[]): string {
  if (items.length === 0) {
    return 'No contacts matched.';
  }
  return items
    .map((item) => `${item.companyName} <${item.primaryContactEmail}> ${item.planCode}`)
    .join('\n');
}

/** Same shape as the ticket search, over the customer directory. */
export function registerCustomerDirectoryTool(server: McpServer, ctx: ToolContext): void {
  server.registerTool(
    'customer_directory_search',
    {
      title: 'Search the customer directory',
      description:
        'Find contacts on the account by company, email, status, plan or country, ' +
        'e.g. field "plan" value "growth-annual".',
      inputSchema: {
        field: z
          .enum(['company', 'email', 'status', 'plan', 'country'])
          .describe('Which directory attribute to match on'),
        value: z.string().min(1).max(160),
        accountId: z.string().regex(ACCOUNT_REFERENCE).optional(),
        limit: z.number().int().min(1).max(25).optional(),
      },
    },
    async ({ field, value, accountId, limit }) => {
      let scope: string;
      try {
        scope = accountScope(ctx, accountId);
      } catch (error) {
        return { content: [{ type: 'text', text: (error as Error).message }], isError: true };
      }

      const attribute = FILTERABLE_ATTRIBUTES[field as FilterableField];
      const result = await documentClient.send(
        new ScanCommand({
          TableName: tables.customers,
          FilterExpression: '#field = :value AND accountId = :accountId',
          ExpressionAttributeNames: { '#field': attribute },
          ExpressionAttributeValues: {
            ':value': value,
            ':accountId': scope,
          },
          Limit: limit ?? 25,
        }),
      );

      const items = (result.Items ?? []) as Record<string, unknown>[];
      return {
        content: [{ type: 'text', text: renderContacts(items) }],
        structuredContent: { matched: items.length, accountId: scope },
      };
    },
  );
}
