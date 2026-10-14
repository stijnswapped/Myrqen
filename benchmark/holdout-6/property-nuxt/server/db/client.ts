import { drizzle } from 'drizzle-orm/node-postgres'
import { Pool } from 'pg'
import * as schema from './schema'

let pool: Pool | undefined

/**
 * One pg pool per Nitro worker. Wrapping it in drizzle is cheap, so we do that
 * per call and keep the pool in module scope.
 */
export function useDb() {
  const config = useRuntimeConfig()

  if (!pool) {
    pool = new Pool({
      connectionString: config.databaseUrl,
      max: Number(config.databasePoolSize) || 10,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 5_000,
      ssl: config.databaseCa
        ? { ca: config.databaseCa, rejectUnauthorized: true }
        : undefined,
    })
  }

  return drizzle(pool, { schema })
}

export type Db = ReturnType<typeof useDb>
