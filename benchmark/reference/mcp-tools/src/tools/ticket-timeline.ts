import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { GetCommand, QueryCommand } from '@aws-sdk/lib-dynamodb';
import { z } from 'zod';
import { documentClient, tables } from '../config/environment.js';
import { accountScope, type ToolContext } from '../auth/sessions.js';

const TICKET_REFERENCE = /^TCK-\d{4,8}$/;
const ACCOUNT_REFERENCE = /^acct_[0-9a-z]{8,32}$/;

interface TicketEvent {
  eventKey: string;
  kind: string;
  actor: string;
  createdAt: string;
  summary: string;
}

function renderTimeline(ticket: Record<string, unknown>, events: TicketEvent[]): string {
  const header = `Ticket ${ticket.ticketId} (${ticket.ticketStatus}) - ${ticket.subject}`;
  if (events.length === 0) {
    return `${header}\n\nNothing has happened on this ticket yet.`;
  }
  const rows = events.map(
    (event) => `${event.createdAt}  ${event.kind.padEnd(14)} ${event.actor}: ${event.summary}`,
  );
  return [header, '', ...rows].join('\n');
}

/**
 * The same ticket read as `support_ticket_get`, plus everything that has
 * happened on it. Used by the summarise-this-ticket flow.
 */
export function registerTicketTimelineTool(server: McpServer, ctx: ToolContext): void {
  server.registerTool(
    'support_ticket_history',
    {
      title: 'Read a ticket with its timeline',
      description:
        'Fetch a ticket together with the events recorded against it, oldest first. ' +
        'Over stdio pass accountId; over HTTP the session decides which account is in scope.',
      inputSchema: {
        ticketId: z.string().regex(TICKET_REFERENCE, 'Ticket references look like TCK-40219'),
        accountId: z
          .string()
          .regex(ACCOUNT_REFERENCE)
          .optional()
          .describe('Only used when the server runs over stdio'),
        limit: z.number().int().min(1).max(200).optional(),
      },
    },
    async ({ ticketId, accountId, limit }) => {
      let scope: string;
      try {
        scope = accountScope(ctx, accountId);
      } catch (error) {
        return {
          content: [{ type: 'text', text: (error as Error).message }],
          isError: true,
        };
      }

      const header = await documentClient.send(
        new GetCommand({
          TableName: tables.tickets,
          Key: { ticketId },
        }),
      );

      const ticket = header.Item;
      if (!ticket || ticket.accountId !== scope) {
        // Deliberately the same answer for "no such ticket" and "not yours", so
        // this tool cannot be used to probe for other customers' references.
        return {
          content: [{ type: 'text', text: `No ticket ${ticketId} on account ${scope}.` }],
          isError: true,
        };
      }

      const timeline = await documentClient.send(
        new QueryCommand({
          TableName: tables.ticketEvents,
          KeyConditionExpression: 'accountId = :accountId AND begins_with(eventKey, :prefix)',
          ExpressionAttributeValues: {
            ':accountId': scope,
            ':prefix': `${ticketId}#`,
          },
          Limit: limit ?? 50,
        }),
      );

      const events = (timeline.Items ?? []) as TicketEvent[];
      return {
        content: [{ type: 'text', text: renderTimeline(ticket, events) }],
      };
    },
  );
}
