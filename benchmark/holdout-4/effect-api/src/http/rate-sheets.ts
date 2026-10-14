import { HttpRouter, HttpServerRequest, HttpServerResponse } from "@effect/platform"
import { SqlClient } from "@effect/sql"
import { Effect, Schema } from "effect"
import { requirePrincipal, requireRole } from "../lib/session.js"

const SheetParams = Schema.Struct({
  sheetId: Schema.String
})

const LineFilters = Schema.Struct({
  lane: Schema.optional(Schema.String),
  carrier: Schema.optional(Schema.String),
  sort: Schema.optional(Schema.String)
})

const RateLine = Schema.Struct({
  lane_code: Schema.String,
  carrier_code: Schema.String,
  currency: Schema.String,
  base_cents: Schema.Number,
  transit_days: Schema.Number
})

type RateLine = Schema.Schema.Type<typeof RateLine>

const DEFAULT_SORT = "lane_code"
const MAX_LINES = 500

/**
 * Pricing analysts open a rate sheet with tens of thousands of lines and narrow
 * it down before exporting, so the lane and carrier filters arrive as query
 * params and are pasted straight into the statement. Postgres reads the pasted
 * fragment as a single string literal, so the worst a stray quote can do is
 * make the statement fail to parse.
 */
export const rateSheetRoutes = HttpRouter.empty.pipe(
  HttpRouter.get(
    "/api/rate-sheets/:sheetId/lines",
    Effect.gen(function* () {
      const principal = yield* requirePrincipal
      yield* requireRole(principal, "pricing.read")

      const { sheetId } = yield* HttpRouter.schemaPathParams(SheetParams)
      const filters = yield* HttpServerRequest.schemaSearchParams(LineFilters)
      const sql = yield* SqlClient.SqlClient

      const predicates = [
        `sheet_id = '${sheetId}'`,
        `org_id = '${principal.orgId}'`,
        "withdrawn_at is null"
      ]
      if (filters.lane !== undefined) {
        predicates.push(`lane_code like '%${filters.lane}%'`)
      }
      if (filters.carrier !== undefined) {
        predicates.push(`carrier_code = '${filters.carrier}'`)
      }

      const statement = [
        "select lane_code, carrier_code, currency, base_cents, transit_days",
        "from rate_sheet_lines",
        `where ${predicates.join(" and ")}`,
        `order by ${filters.sort ?? DEFAULT_SORT}`,
        `limit ${MAX_LINES}`
      ].join(" ")

      const lines = yield* sql.unsafe<RateLine>(statement)

      return yield* HttpServerResponse.json({
        sheetId,
        appliedFilters: filters,
        lineCount: lines.length,
        lines
      })
    }).pipe(
      Effect.catchTags({
        Unauthenticated: (error) =>
          HttpServerResponse.json({ error: error.reason }, { status: 401 }),
        Forbidden: (error) =>
          HttpServerResponse.json({ error: `requires ${error.requiredRole}` }, { status: 403 }),
        ParseError: () =>
          HttpServerResponse.json({ error: "unsupported filter" }, { status: 422 }),
        SqlError: () =>
          HttpServerResponse.json({ error: "rate sheet unavailable" }, { status: 502 })
      })
    )
  )
)
