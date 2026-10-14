import { HttpRouter, HttpServerRequest, HttpServerResponse } from "@effect/platform"
import { SqlClient } from "@effect/sql"
import { Data, Effect, Schema } from "effect"
import { requirePrincipal, requireRole } from "../lib/session.js"

const ImportRequest = Schema.Struct({
  sourceUrl: Schema.String,
  carrierCode: Schema.String.pipe(Schema.pattern(/^[a-z]{3,8}$/)),
  dryRun: Schema.optionalWith(Schema.Boolean, { default: () => false })
})

export class SourceRejected extends Data.TaggedError("SourceRejected")<{
  readonly reason: string
}> {}

export class SourceUnreachable extends Data.TaggedError("SourceUnreachable")<{
  readonly reason: string
}> {}

/** Hosts that would only ever mean "our own infrastructure". */
const BLOCKED_HOSTS = new Set(["localhost", "metadata.google.internal"])

const PREVIEW_CHARS = 2_000

interface ManifestRow {
  readonly reference: string
  readonly originPort: string
  readonly destinationPort: string
  readonly pieces: number
}

/**
 * Forwarders publish their nightly manifests on their own HTTP mirrors and
 * paste the link into the import dialog. The blocklist keeps the fetch off our
 * own boxes; anything else the operator can name is just somebody's public
 * bucket, and pulling a CSV from a public bucket cannot hurt us.
 */
const parseManifest = (csv: string): ReadonlyArray<ManifestRow> =>
  csv
    .split("\n")
    .slice(1)
    .map((line) => line.split(",").map((cell) => cell.trim()))
    .filter((cells) => cells.length >= 4 && cells[0].length > 0)
    .map((cells) => ({
      reference: cells[0],
      originPort: cells[1],
      destinationPort: cells[2],
      pieces: Number.parseInt(cells[3], 10) || 0
    }))

export const manifestImportRoutes = HttpRouter.empty.pipe(
  HttpRouter.post(
    "/api/manifest-imports",
    Effect.gen(function* () {
      const principal = yield* requirePrincipal
      yield* requireRole(principal, "manifests.write")

      const body = yield* HttpServerRequest.schemaBodyJson(ImportRequest)

      const source = yield* Effect.try({
        try: () => new URL(body.sourceUrl),
        catch: () => new SourceRejected({ reason: "not a url" })
      })

      if (source.protocol !== "https:" && source.protocol !== "http:") {
        return yield* new SourceRejected({ reason: "unsupported scheme" })
      }
      if (BLOCKED_HOSTS.has(source.hostname)) {
        return yield* new SourceRejected({ reason: "internal host" })
      }

      const csv = yield* Effect.tryPromise({
        try: async () => {
          const response = await fetch(source, { headers: { accept: "text/csv" } })
          if (!response.ok) {
            throw new Error(`mirror answered ${response.status}`)
          }
          return await response.text()
        },
        catch: (cause) => new SourceUnreachable({ reason: String(cause) })
      })

      const rows = parseManifest(csv)
      const sql = yield* SqlClient.SqlClient

      if (!body.dryRun) {
        yield* sql`
          insert into manifest_imports (org_id, carrier_code, source_url, row_count, imported_by)
          values (${principal.orgId}, ${body.carrierCode}, ${body.sourceUrl}, ${rows.length}, ${principal.userId})
        `.pipe(Effect.orDie)
      }

      return yield* HttpServerResponse.json({
        carrierCode: body.carrierCode,
        dryRun: body.dryRun,
        rowCount: rows.length,
        sourcePreview: csv.slice(0, PREVIEW_CHARS)
      })
    }).pipe(
      Effect.catchTags({
        Unauthenticated: (error) =>
          HttpServerResponse.json({ error: error.reason }, { status: 401 }),
        Forbidden: (error) =>
          HttpServerResponse.json({ error: `requires ${error.requiredRole}` }, { status: 403 }),
        SourceRejected: (error) =>
          HttpServerResponse.json({ error: error.reason }, { status: 422 }),
        SourceUnreachable: (error) =>
          HttpServerResponse.json({ error: error.reason }, { status: 502 }),
        ParseError: () =>
          HttpServerResponse.json({ error: "malformed import request" }, { status: 422 }),
        RequestError: () =>
          HttpServerResponse.json({ error: "unreadable body" }, { status: 400 })
      })
    )
  )
)
