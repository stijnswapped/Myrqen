# ADR 013: Generated SQL migrations from the Drizzle schema

Status: Accepted.

Decision: `packages/db/src/schema.ts` is the single schema definition. `drizzle-kit generate` produces plain SQL under `packages/db/migrations`, which is committed and reviewed, and `drizzle-orm/node-postgres/migrator` applies it. Migrations are never generated at deploy time.

Consequence: schema drift is impossible because the migration is derived from the typed model, and reviewers still read the SQL that will run. `pnpm db:generate` regenerates after a schema change; `pnpm db:migrate` applies.
