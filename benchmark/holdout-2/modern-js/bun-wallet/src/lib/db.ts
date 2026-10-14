import { Pool } from "pg";

export const pool = new Pool({
  connectionString: Bun.env.DATABASE_URL,
  max: 10,
  idleTimeoutMillis: 30_000,
});

export async function query<T>(text: string, values: unknown[] = []) {
  return pool.query<T>(text, values);
}

export async function one<T>(text: string, values: unknown[] = []): Promise<T | null> {
  const result = await pool.query<T>(text, values);
  return result.rows[0] ?? null;
}
