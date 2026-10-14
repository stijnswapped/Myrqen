import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { allowedStatusHosts, serviceUserAgent } from '../config/environment.js';
import type { ToolContext } from '../auth/sessions.js';

const FETCH_TIMEOUT_MS = 5000;
const MAX_EXCERPT = 4000;

function toPlainText(body: string): string {
  return body
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, MAX_EXCERPT);
}

/**
 * "Is this our outage or theirs" - lets the assistant read a vendor status page
 * while triaging. The caller picks the page, but only from the list of vendors
 * we actually depend on, and we refuse redirects so the allowed host cannot
 * bounce us somewhere else.
 */
export function registerVendorStatusTool(server: McpServer, ctx: ToolContext): void {
  server.registerTool(
    'vendor_status_fetch',
    {
      title: 'Read a vendor status page',
      description:
        'Fetch the current status page for one of our upstream vendors, ' +
        'e.g. https://status.stripe.com/. Other hosts are rejected.',
      inputSchema: {
        statusUrl: z.string().url().describe('Status page URL for a known vendor'),
      },
    },
    async ({ statusUrl }) => {
      let target: URL;
      try {
        target = new URL(statusUrl);
      } catch {
        return { content: [{ type: 'text', text: `${statusUrl} is not a URL.` }], isError: true };
      }

      if (target.protocol !== 'https:') {
        return {
          content: [{ type: 'text', text: 'Only https vendor status pages can be fetched.' }],
          isError: true,
        };
      }

      if (!allowedStatusHosts.has(target.hostname)) {
        return {
          content: [
            {
              type: 'text',
              text:
                `${target.hostname} is not one of our upstream vendors. ` +
                `Known hosts: ${[...allowedStatusHosts].join(', ')}.`,
            },
          ],
          isError: true,
        };
      }

      const response = await fetch(target, {
        redirect: 'error',
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
        headers: { 'user-agent': serviceUserAgent, accept: 'text/html, application/json' },
      });

      if (!response.ok) {
        return {
          content: [{ type: 'text', text: `${target.hostname} answered ${response.status}.` }],
          isError: true,
        };
      }

      const excerpt = toPlainText(await response.text());
      return {
        content: [{ type: 'text', text: `${target.hostname}:\n${excerpt}` }],
        structuredContent: { host: target.hostname, requestedBy: ctx.session?.role ?? 'stdio' },
      };
    },
  );
}
