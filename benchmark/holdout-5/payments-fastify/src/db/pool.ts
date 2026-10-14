import { Pool, type PoolClient, type QueryResult, type QueryResultRow } from 'pg';

import { config } from '../config/env.js';

/**
 * One pool per process. The settlement API is read-heavy during the day and
 * write-heavy during the nightly payout run, so the pool is sized generously
 * and hands back clients quickly.
 */
export const pool = new Pool({
  connectionString: config.databaseUrl,
  max: config.databasePoolMax,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 5_000,
  application_name: 'merchant-settlement-service',
});

pool.on('error', (error) => {
  // An idle client died on us; pg replaces it on the next checkout, we only
  // need the breadcrumb in the logs.
  console.error('[db] idle client error', error);
});

export async function query<T extends QueryResultRow>(
  text: string,
  values: readonly unknown[] = [],
): Promise<QueryResult<T>> {
  return pool.query<T>(text, values as unknown[]);
}

export async function queryOne<T extends QueryResultRow>(
  text: string,
  values: readonly unknown[] = [],
): Promise<T | undefined> {
  const result = await query<T>(text, values);
  return result.rows[0];
}

export async function withTransaction<T>(handler: (client: PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const outcome = await handler(client);
    await client.query('COMMIT');
    return outcome;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

export async function closePool(): Promise<void> {
  await pool.end();
}
