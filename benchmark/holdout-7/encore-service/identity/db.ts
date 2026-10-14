import { SQLDatabase } from "encore.dev/storage/sqldb";

/**
 * One Postgres database for the whole app. `identity` owns the migrations
 * because organizations and memberships are the root of every other table's
 * foreign keys. The other services attach to it with
 * `SQLDatabase.named("ridgeline")` rather than declaring their own.
 */
export const ridgeline = new SQLDatabase("ridgeline", {
  migrations: "./migrations",
});
