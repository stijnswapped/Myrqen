/**
 * Runtime configuration for the merchant settlement service.
 *
 * Secrets are read from the process environment at boot. Anything the service
 * cannot run correctly without is required, so a half-configured deploy fails
 * on start-up instead of quietly falling back to a shared development value.
 */

function requireEnv(name: string): string {
  const value = process.env[name];
  if (value === undefined || value.trim() === '') {
    throw new Error(`Missing required environment variable ${name}`);
  }
  return value;
}

function optionalInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === '') {
    return fallback;
  }
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isInteger(parsed)) {
    throw new Error(`Environment variable ${name} must be an integer`);
  }
  return parsed;
}

export interface ServiceConfig {
  readonly nodeEnv: string;
  readonly port: number;
  readonly databaseUrl: string;
  readonly databasePoolMax: number;
  readonly sessionCookieName: string;
  readonly sessionCookieSecret: string;
  readonly processorWebhookSecret: string;
  readonly statementArchiveRoot: string;
  readonly remittanceArchiveRoot: string;
  readonly payoutReleaseWindowHours: number;
}

export const config: ServiceConfig = Object.freeze({
  nodeEnv: process.env.NODE_ENV ?? 'development',
  port: optionalInt('PORT', 8081),
  databaseUrl: requireEnv('DATABASE_URL'),
  databasePoolMax: optionalInt('DATABASE_POOL_MAX', 12),
  sessionCookieName: process.env.SESSION_COOKIE_NAME ?? 'mq_merchant_session',
  sessionCookieSecret: requireEnv('SESSION_COOKIE_SECRET'),
  processorWebhookSecret: requireEnv('PROCESSOR_WEBHOOK_SECRET'),
  statementArchiveRoot: process.env.STATEMENT_ARCHIVE_ROOT ?? '/var/lib/settlement/statements',
  remittanceArchiveRoot: process.env.REMITTANCE_ARCHIVE_ROOT ?? '/var/lib/settlement/remittances',
  payoutReleaseWindowHours: optionalInt('PAYOUT_RELEASE_WINDOW_HOURS', 24),
});
