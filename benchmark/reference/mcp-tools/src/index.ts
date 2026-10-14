#!/usr/bin/env node
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import type { ToolContext } from './auth/sessions.js';
import { registerRunbookLibrary } from './resources/runbook-library.js';
import { registerTicketAttachments } from './resources/ticket-attachments.js';
import { registerAccountCreditTools } from './tools/account-credits.js';
import { registerCustomerDirectoryTool } from './tools/customer-directory.js';
import { registerKnowledgeImportTool } from './tools/knowledge-import.js';
import { registerSubscriptionChangeTools } from './tools/subscription-changes.js';
import { registerTicketLookupTool } from './tools/ticket-lookup.js';
import { registerTicketSearchTool } from './tools/ticket-search.js';
import { registerTicketTimelineTool } from './tools/ticket-timeline.js';
import { registerVendorStatusTool } from './tools/vendor-status.js';

export const serverInfo = { name: 'ledgerline-support', version: '2.4.1' };

/**
 * Build a server instance for one caller. Both entry points use this, so the
 * tools and resources behave identically over stdio and over HTTP; the only
 * difference between the two is what is in the context.
 */
export function createSupportServer(ctx: ToolContext): McpServer {
  const server = new McpServer(serverInfo, {
    instructions:
      'Ledgerline support desk. Read tickets before answering, cite a runbook when you ' +
      'recommend an action, and never promise a credit you have not applied.',
  });

  registerTicketLookupTool(server, ctx);
  registerTicketTimelineTool(server, ctx);
  registerTicketSearchTool(server, ctx);
  registerCustomerDirectoryTool(server, ctx);
  registerAccountCreditTools(server, ctx);
  registerSubscriptionChangeTools(server, ctx);
  registerKnowledgeImportTool(server, ctx);
  registerVendorStatusTool(server, ctx);
  registerRunbookLibrary(server, ctx);
  registerTicketAttachments(server, ctx);

  server.registerPrompt(
    'triage_ticket',
    {
      title: 'Triage a ticket',
      description: 'Walk a ticket through our triage checklist and draft the first reply.',
      argsSchema: {
        ticketId: z.string().regex(/^TCK-\d{4,8}$/),
        tone: z.enum(['neutral', 'apologetic']).optional(),
      },
    },
    ({ ticketId, tone }) => ({
      messages: [
        {
          role: 'user',
          content: {
            type: 'text',
            text:
              `Triage ${ticketId}. Read the ticket and its history first, then say which ` +
              `queue it belongs in, what the customer is actually asking for, and draft a ` +
              `${tone ?? 'neutral'} reply. Quote a runbook if one applies.`,
          },
        },
      ],
    }),
  );

  return server;
}

/**
 * stdio entry point: an engineer's MCP client spawns this binary, so the caller
 * is the person who started the process. There is no second party on the other
 * end of the pipe to authenticate, and the process can only reach what that
 * engineer's own AWS credentials can reach, so the context has no session.
 */
async function main(): Promise<void> {
  const server = createSupportServer({ session: null });
  await server.connect(new StdioServerTransport());
  process.stderr.write(`${serverInfo.name} ${serverInfo.version} ready on stdio\n`);
}

main().catch((error: unknown) => {
  process.stderr.write(`fatal: ${(error as Error).message}\n`);
  process.exit(1);
});
