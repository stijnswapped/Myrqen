import { HttpRouter, HttpServerRequest, HttpServerResponse } from "@effect/platform"
import { SqlClient } from "@effect/sql"
import { Config, Data, Effect, Schema } from "effect"
import { requirePrincipal, requireRole } from "../lib/session.js"

const SyncRequest = Schema.Struct({
  sourceUrl: Schema.String,
  carrierCode: Schema.String.pipe(Schema.pattern(/^[a-z]{3,8}$/))
})

export class SourceRejected extends Data.TaggedError("SourceRejected")<{
  readonly reason: string
}> {}

export class SourceUnreachable extends Data.TaggedError("SourceUnreachable")<{
  readonly reason: string
}> {}

const PREVIEW_CHARS = 2_000

/**
 * Pulls a carrier's published rate sheet from their mirror. The operator still
 * types the link, but the host has to be one the platform team put in
 * RATE_MIRROR_HOSTS, the scheme and port are pinned, and redirects are refused
 * so the allowed host cannot hand the fetch on somewhere else.
 */
export const rateSheetSyncRoutes = HttpRouter.empty.pipe(
  HttpRouter.post(
    "/api/rate-sheet-syncs",
    Effect.gen(function* () {
      const principal = yield* requirePrincipal
      yield* requireRole(principal, "pricing.write")

      const allowedHosts = yield* Config.hashSet(Config.string(), "RATE_MIRROR_HOSTS")
      const body = yield* HttpServerRequest.schemaBodyJson(SyncRequest)

      const source = yield* Effect.try({
        try: () => new URL(body.sourceUrl),
        catch: () => new SourceRejected({ reason: "not a url" })
      })

      if (source.protocol !== "https:") {
        return yield* new SourceRejected({ reason: "https only" })
      }
      if (source.port !== "" && source.port !== "443") {
        return yield* new SourceRejected({ reason: "non standard port" })
      }
      if (!allowedHosts.has(source.hostname.toLowerCase())) {
        return yield* new SourceRejected({ reason: "mirror not registered" })
      }

      const csv = yield* Effect.tryPromise({
        try: async () => {
          const response = await fetch(source, {
            headers: { accept: "text/csv" },
            redirect: "error"
          })
          if (!response.ok) {
            throw new Error(`mirror answered ${response.status}`)
          }
          return await response.text()
        },
        catch: (cause) => new SourceUnreachable({ reason: String(cause) })
      })

      const lineCount = csv.split("\n").filter((line) => line.trim().length > 0).length - 1
      const sql = yield* SqlClient.SqlClient

      yield* sql`
        insert into rate_sheet_syncs (org_id, carrier_code, source_url, line_count, started_by)
        values (${principal.orgId}, ${body.carrierCode}, ${body.sourceUrl}, ${lineCount}, ${principal.userId})
      `.pipe(Effect.orDie)

      return yield* HttpServerResponse.json({
        carrierCode: body.carrierCode,
        lineCount,
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
        ConfigError: () =>
          HttpServerResponse.json({ error: "sync not configured" }, { status: 500 }),
        ParseError: () =>
          HttpServerResponse.json({ error: "malformed sync request" }, { status: 422 }),
        RequestError: () =>
          HttpServerResponse.json({ error: "unreadable body" }, { status: 400 })
      })
    )
  )
)
