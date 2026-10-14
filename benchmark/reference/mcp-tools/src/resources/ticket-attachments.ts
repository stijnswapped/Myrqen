import { ResourceTemplate, type McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { QueryCommand } from '@aws-sdk/lib-dynamodb';
import { readFile } from 'node:fs/promises';
import { basename, resolve, sep } from 'node:path';
import { documentClient, storagePaths, tables } from '../config/environment.js';
import type { ToolContext } from '../auth/sessions.js';

interface AttachmentRecord {
  ticketId: string;
  attachmentKey: string;
  accountId: string;
  originalFilename: string;
  /** Path under the attachment mount, written by the upload service. */
  storageKey: string;
  contentType: string;
}

function firstValue(value: string | string[] | undefined): string {
  return Array.isArray(value) ? (value[0] ?? '') : (value ?? '');
}

/**
 * Customer attachments, exposed as resources so a client can pull the log file
 * a customer pasted into a ticket.
 *
 * The index is the only thing allowed to name a file: we look the attachment
 * record up by ticket, match the caller's file name against the name we
 * recorded, and then read the storage key we wrote ourselves at upload time.
 */
export function registerTicketAttachments(server: McpServer, ctx: ToolContext): void {
  server.registerResource(
    'ticket-attachment',
    new ResourceTemplate('attachment://tickets/{ticketId}/{filename}', { list: undefined }),
    {
      title: 'Ticket attachment',
      description:
        'A file a customer attached to a ticket, e.g. ' +
        'attachment://tickets/TCK-40219/webhook-log.txt',
    },
    async (uri, variables) => {
      const ticketId = firstValue(variables.ticketId as string | string[] | undefined);
      const filename = firstValue(variables.filename as string | string[] | undefined);

      const indexed = await documentClient.send(
        new QueryCommand({
          TableName: tables.ticketAttachments,
          KeyConditionExpression: 'ticketId = :ticketId',
          FilterExpression: 'originalFilename = :filename',
          ExpressionAttributeValues: {
            ':ticketId': ticketId,
            ':filename': basename(filename),
          },
          Limit: 1,
        }),
      );

      const record = (indexed.Items ?? [])[0] as AttachmentRecord | undefined;
      if (!record) {
        throw new Error(`${ticketId} has no attachment called ${basename(filename)}`);
      }

      if (ctx.session && record.accountId !== ctx.session.accountId) {
        // Same message as the miss above: a session must not be able to tell
        // "no such file" from "another customer's file".
        throw new Error(`${ticketId} has no attachment called ${basename(filename)}`);
      }

      const onDisk = resolve(storagePaths.attachmentRoot, record.storageKey);
      if (!onDisk.startsWith(storagePaths.attachmentRoot + sep)) {
        throw new Error(`Attachment ${record.attachmentKey} is outside the attachment store`);
      }

      return {
        contents: [
          {
            uri: uri.href,
            mimeType: record.contentType,
            text: await readFile(onDisk, 'utf8'),
          },
        ],
      };
    },
  );
}
