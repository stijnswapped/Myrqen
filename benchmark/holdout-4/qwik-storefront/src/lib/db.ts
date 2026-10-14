import { Pool } from 'pg';

const connectionString = process.env.STOREFRONT_DATABASE_URL;

if (!connectionString) {
  throw new Error('STOREFRONT_DATABASE_URL must be set before the storefront boots');
}

/**
 * One pooled client for the whole storefront. Statement text is cached by the
 * pooler, so keep customer data out of the statement string and pass it through
 * the values array instead.
 */
export const pool = new Pool({
  connectionString,
  max: Number(process.env.STOREFRONT_DB_POOL ?? 8),
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000,
  application_name: 'verdant-storefront',
});

/** Root of the mounted document archive: invoices, receipts, packing slips. */
export const ARCHIVE_ROOT = process.env.DOCUMENT_ARCHIVE_ROOT ?? '/srv/verdant/archive';

/** Nothing paginated in the account area ever returns more than this. */
export const MAX_PAGE_SIZE = 200;

export type SubscriptionStatus = 'trialing' | 'active' | 'past_due' | 'cancelled';

export type MoneyCents = number;
