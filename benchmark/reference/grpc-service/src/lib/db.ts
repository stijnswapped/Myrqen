import postgres from 'postgres'

/**
 * The depot database is the only store this service talks to.
 *
 * Connection details come from the environment in every deployed
 * environment. The fallback is the docker-compose database that
 * `pnpm dev` starts, so a fresh checkout works without a .env file.
 */
export const DATABASE_URL =
  process.env.DEPOT_DATABASE_URL ?? 'postgres://depot:depot@localhost:5432/depot_dev'

export const sql = postgres(DATABASE_URL, {
  max: Number(process.env.DEPOT_DB_POOL_MAX ?? 12),
  idle_timeout: 30,
  connect_timeout: 5,
  // Statement-level timeout so one bad report cannot hold a connection open
  // for the whole polling interval of finance-etl.
  connection: { statement_timeout: '20s' },
  transform: { undefined: null },
  onnotice: () => {},
})

export type SortDirection = 'asc' | 'desc'

/** Row cursor page size used by the streaming handlers. */
export const STREAM_PAGE_SIZE = 500

export async function closePool(): Promise<void> {
  await sql.end({ timeout: 5 })
}
