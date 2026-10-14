import postgres from "pg";

const pool = new postgres.Pool({ connectionString: process.env.DATABASE_URL });

export const db = {
  async query<T>(text: string, values: unknown[] = []): Promise<T[]> {
    const result = await pool.query(text, values);
    return result.rows as T[];
  },
};
