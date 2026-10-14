import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { PutCommand } from '@aws-sdk/lib-dynamodb';
import { z } from 'zod';
import {
  documentClient,
  serviceUserAgent,
  tables,
} from '../config/environment.js';
import { accountScope, type ToolContext } from '../auth/sessions.js';

const ACCOUNT_REFERENCE = /^acct_[0-9a-z]{8,32}$/;
const MAX_EXCERPT = 6000;

function toPlainText(html: string): string {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, MAX_EXCERPT);
}

/**
 * Pull a help-centre page into the knowledge cache so the assistant can quote
 * it back at the customer instead of paraphrasing from memory.
 *
 * Zod has already proved the argument is a well formed absolute URL, and in
 * practice the model only ever passes links off help.ledgerline.com because
 * that is all it sees in a ticket, so a plain fetch is fine here.
 */
export function registerKnowledgeImportTool(server: McpServer, ctx: ToolContext): void {
  server.registerTool(
    'knowledge_article_import',
    {
      title: 'Import a help-centre article',
      description:
        'Fetch a published help-centre page and cache it against the account so it can be ' +
        'quoted in a reply. Pass the article URL exactly as it appears in the ticket.',
      inputSchema: {
        sourceUrl: z.string().url().describe('Absolute URL of the article to import'),
        slug: z
          .string()
          .regex(/^[a-z0-9-]{3,80}$/)
          .describe('Cache key for the article, e.g. proration-explained'),
        accountId: z.string().regex(ACCOUNT_REFERENCE).optional(),
      },
    },
    async ({ sourceUrl, slug, accountId }) => {
      let scope: string;
      try {
        scope = accountScope(ctx, accountId);
      } catch (error) {
        return { content: [{ type: 'text', text: (error as Error).message }], isError: true };
      }

      const response = await fetch(sourceUrl, {
        headers: { 'user-agent': serviceUserAgent, accept: 'text/html, text/plain' },
      });

      if (!response.ok) {
        return {
          content: [
            { type: 'text', text: `${sourceUrl} answered ${response.status} ${response.statusText}.` },
          ],
          isError: true,
        };
      }

      const excerpt = toPlainText(await response.text());

      await documentClient.send(
        new PutCommand({
          TableName: tables.knowledgeArticles,
          Item: {
            accountId: scope,
            slug,
            sourceUrl,
            excerpt,
            importedAt: new Date().toISOString(),
            importedBy: ctx.session?.displayName ?? 'local operator',
          },
        }),
      );

      return {
        content: [{ type: 'text', text: excerpt }],
        structuredContent: { slug, characters: excerpt.length },
      };
    },
  );
}
