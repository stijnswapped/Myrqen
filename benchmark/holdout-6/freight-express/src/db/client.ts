import 'dotenv/config';
import { drizzle } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';

import * as schema from './schema.js';

const connectionString = process.env.DATABASE_URL;
if (!connectionString) {
  throw new Error('DATABASE_URL is not set');
}

/**
 * One pool per process. The freight desk runs long lived HTTP workers, so the
 * pool is sized for the request concurrency of a single worker rather than for
 * the whole fleet.
 */
export const pool = new Pool({
  connectionString,
  max: Number(process.env.PGPOOL_MAX ?? 10),
  idleTimeoutMillis: 30_000,
  statement_timeout: 15_000,
  ssl: process.env.PGSSL === 'disable' ? undefined : { rejectUnauthorized: true },
});

export const db = drizzle(pool, { schema });

export type Database = typeof db;
export { schema };
