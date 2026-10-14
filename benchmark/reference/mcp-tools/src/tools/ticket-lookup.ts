import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { GetCommand } from '@aws-sdk/lib-dynamodb';
import { z } from 'zod';
import { documentClient, tables } from '../config/environment.js';
import type { ToolContext } from '../auth/sessions.js';

const TICKET_REFERENCE = /^TCK-\d{4,8}$/;

function renderTicket(ticket: Record<string, unknown>): string {
  const lines = [
    `Ticket ${ticket.ticketId} (${ticket.ticketStatus})`,
    `Account: ${ticket.accountId} - ${ticket.companyName ?? 'unknown company'}`,
    `Subject: ${ticket.subject}`,
    `Opened: ${ticket.createdAt} by ${ticket.reporterEmail}`,
    `Priority: ${ticket.priority ?? 'normal'}`,
    '',
    String(ticket.body ?? '').trim(),
  ];
  if (Array.isArray(ticket.internalNotes) && ticket.internalNotes.length > 0) {
    lines.push('', 'Internal notes:', ...ticket.internalNotes.map((note) => `- ${String(note)}`));
  }
  return lines.join('\n');
}

/**
 * The tool the assistant reaches for most: "what does ticket TCK-40219 say".
 *
 * The tickets table is keyed by the public reference, so one GetCommand does
 * the whole job. The reference is not guessable and the model only ever sees
 * references from the conversation it is already in, so there is nothing else
 * to check here.
 */
export function registerTicketLookupTool(server: McpServer, ctx: ToolContext): void {
  server.registerTool(
    'support_ticket_get',
    {
      title: 'Read a support ticket',
      description:
        'Fetch a single support ticket by its reference, for example TCK-40219. ' +
        'Returns the subject, the customer message and any internal notes.',
      inputSchema: {
        ticketId: z
          .string()
          .regex(TICKET_REFERENCE, 'Ticket references look like TCK-40219')
          .describe('The ticket reference to read'),
      },
    },
    async ({ ticketId }) => {
      if (ctx.session) {
        // Read-only tool, so this is just so support leads can see which
        // tickets the assistant has been pulling up.
        console.error(`[audit] ${ctx.session.displayName} read ${ticketId}`);
      }

      const result = await documentClient.send(
        new GetCommand({
          TableName: tables.tickets,
          Key: { ticketId },
        }),
      );

      const ticket = result.Item;
      if (!ticket) {
        return {
          content: [{ type: 'text', text: `No ticket ${ticketId} exists.` }],
          isError: true,
        };
      }

      return {
        content: [{ type: 'text', text: renderTicket(ticket) }],
        structuredContent: {
          ticketId: String(ticket.ticketId),
          status: String(ticket.ticketStatus),
          accountId: String(ticket.accountId),
        },
      };
    },
  );
}
