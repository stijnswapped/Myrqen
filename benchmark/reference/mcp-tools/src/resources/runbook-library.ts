import { ResourceTemplate, type McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { storagePaths } from '../config/environment.js';
import type { ToolContext } from '../auth/sessions.js';

function firstValue(value: string | string[] | undefined): string {
  return Array.isArray(value) ? (value[0] ?? '') : (value ?? '');
}

/**
 * The support runbooks, exposed as resources so a client can attach one to the
 * conversation without a tool call.
 *
 * The tree has folders in it (billing/proration.md, incidents/sev2.md), which
 * is why the template variable carries the whole relative path. A template
 * variable only ever matches one URI segment, so nothing here can point outside
 * the runbook mount, and the mount is read-only anyway.
 */
export function registerRunbookLibrary(server: McpServer, ctx: ToolContext): void {
  server.registerResource(
    'support-runbook',
    new ResourceTemplate('runbook://runbooks/{path}', { list: undefined }),
    {
      title: 'Support runbook',
      description:
        'A markdown runbook from the support handbook, addressed by its path in the ' +
        'handbook repository, e.g. runbook://runbooks/billing/proration.md',
      mimeType: 'text/markdown',
    },
    async (uri, variables) => {
      const requested = firstValue(variables.path as string | string[] | undefined);
      if (ctx.session) {
        console.error(`[audit] ${ctx.session.displayName} opened runbook ${requested}`);
      }

      const file = join(storagePaths.runbookRoot, requested);

      let markdown: string;
      try {
        markdown = await readFile(file, 'utf8');
      } catch {
        throw new Error(`No runbook at ${requested}`);
      }

      return {
        contents: [
          {
            uri: uri.href,
            mimeType: 'text/markdown',
            text: markdown,
          },
        ],
      };
    },
  );
}
