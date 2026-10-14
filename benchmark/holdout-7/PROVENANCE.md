# Run 7 — provenance

Recorded **before** any case was authored, so the score below cannot be attributed to an
engine that was changed while the corpus was being written.

| | |
|---|---|
| engine source hash | `d32051b4a9e8` |
| working tree | `8c9937f` |
| engine files hashed | 40 (`packages/scan/src/**/*.ts`) |
| engine dirty at freeze | yes — 25 modified files, this week's uncommitted work |
| authored | 2026-08-25 |
| scored | once, per ruling U1 |

The hash is `sha256` over every `.ts` under `packages/scan/src`, concatenated in sorted
path order with each file preceded by its relative path — the same function
`score-corpus.mjs` uses, so the figure it writes into `holdout-7-last-run.json` must match
this one. If it does not, the engine changed during authoring and the run is void.

## Stacks

Five frameworks and five data layers, none used by corpora 1–6 (ruling U5). Chosen on
real-world usage, not on what this engine handles — two of the five use document stores
the engine has never seen, which is the point.

| Family | Framework | Data layer |
|---|---|---|
| `firebase-functions` | Firebase Cloud Functions v2 | Firestore (Admin SDK) |
| `azure-functions` | Azure Functions Node v4 | Cosmos DB SDK |
| `strapi-cms` | Strapi 5 | Document Service API over Postgres |
| `medusa-commerce` | Medusa 2 API routes | MikroORM over Postgres |
| `encore-service` | Encore.ts | Encore `SQLDatabase` raw SQL over Postgres |
