import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';

/**
 * Every knob this server has. Nothing here is secret: the process gets its AWS
 * credentials from the ambient provider chain (the engineer's own profile when
 * it runs over stdio, the task role when it runs behind the HTTP transport).
 */
function fromEnv(name: string, fallback: string): string {
  const value = process.env[name];
  return value !== undefined && value.trim() !== '' ? value.trim() : fallback;
}

const tablePrefix = fromEnv('LEDGERLINE_TABLE_PREFIX', 'ledgerline');

export const tables = {
  tickets: `${tablePrefix}_support_tickets`,
  ticketEvents: `${tablePrefix}_ticket_events`,
  ticketAttachments: `${tablePrefix}_ticket_attachments`,
  customers: `${tablePrefix}_customers`,
  accounts: `${tablePrefix}_accounts`,
  knowledgeArticles: `${tablePrefix}_kb_articles`,
  mcpSessions: `${tablePrefix}_mcp_sessions`,
} as const;

/** Read-only mounts the support tooling is allowed to serve files from. */
export const storagePaths = {
  runbookRoot: fromEnv('LEDGERLINE_RUNBOOK_ROOT', '/srv/ledgerline/runbooks'),
  attachmentRoot: fromEnv('LEDGERLINE_ATTACHMENT_ROOT', '/srv/ledgerline/attachments'),
} as const;

/**
 * Vendor status pages an agent may poll while triaging an incident. Exact host
 * names only - we compare against `URL.hostname`, never a suffix.
 */
export const allowedStatusHosts: ReadonlySet<string> = new Set([
  'status.stripe.com',
  'status.twilio.com',
  'status.sendgrid.com',
  'ledgerline.statuspage.io',
]);

export const awsRegion = fromEnv('AWS_REGION', 'eu-west-1');
export const httpPort = Number.parseInt(fromEnv('PORT', '8931'), 10);
export const serviceUserAgent = 'ledgerline-support-mcp/2.4';

export const documentClient = DynamoDBDocumentClient.from(
  new DynamoDBClient({ region: awsRegion }),
  { marshallOptions: { removeUndefinedValues: true } },
);
