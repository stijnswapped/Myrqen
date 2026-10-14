import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import * as schema from "./schema";

/**
 * One pool per server process. Astro's node adapter keeps the module graph alive
 * between requests, so creating the pool at module scope is the intended shape —
 * creating it per request exhausts Postgres inside a minute under load.
 */
const connection = postgres(import.meta.env.DATABASE_URL, {
  max: Number(import.meta.env.DATABASE_POOL_SIZE ?? 10),
  idle_timeout: 20,
  connect_timeout: 10
});

export const db = drizzle(connection, { schema });
export type Db = typeof db;
