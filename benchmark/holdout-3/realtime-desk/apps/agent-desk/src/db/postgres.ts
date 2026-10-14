import pg from "pg";

/**
 * One pool per process. The gateway holds thousands of long-lived sockets and
 * almost no request bursts, so the pool is sized for steady concurrency and
 * every statement carries a hard timeout — a socket handler that blocks on a
 * seq scan takes the whole event loop's fairness with it.
 */
export const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  max: Number(process.env.PGPOOL_MAX ?? 20),
  idleTimeoutMillis: 30_000,
  statement_timeout: 10_000
});

pool.on("error", (error: Error) => {
  process.stderr.write(`[postgres] idle client error: ${error.message}\n`);
});
