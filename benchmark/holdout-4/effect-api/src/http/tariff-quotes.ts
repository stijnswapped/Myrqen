import { HttpRouter, HttpServerRequest, HttpServerResponse } from "@effect/platform"
import { SqlClient } from "@effect/sql"
import { Effect, Schema } from "effect"
import { requirePrincipal, requireRole } from "../lib/session.js"

const QuoteParams = Schema.Struct({
  sheetId: Schema.String
})

const QuoteFilters = Schema.Struct({
  lane: Schema.optional(Schema.String),
  carrier: Schema.optional(Schema.String),
  sort: Schema.optional(Schema.Literal("lane", "cheapest", "fastest"))
})

const QuoteLine = Schema.Struct({
  lane_code: Schema.String,
  carrier_code: Schema.String,
  currency: Schema.String,
  base_cents: Schema.Number,
  transit_days: Schema.Number
})

type QuoteLine = Schema.Schema.Type<typeof QuoteLine>

/** The only orderings the quote grid offers, keyed by the literal it accepts. */
const ORDER_BY = {
  lane: "lane_code asc",
  cheapest: "base_cents asc",
  fastest: "transit_days asc"
} as const

const MAX_LINES = 500

/**
 * Same grid as the rate sheet editor, but read-only and used by the quoting
 * desk. Filters are bound as parameters and the ordering is resolved from a
 * closed table before it ever reaches the statement text.
 */
export const tariffQuoteRoutes = HttpRouter.empty.pipe(
  HttpRouter.get(
    "/api/tariff-quotes/:sheetId/lines",
    Effect.gen(function* () {
      const principal = yield* requirePrincipal
      yield* requireRole(principal, "pricing.read")

      const { sheetId } = yield* HttpRouter.schemaPathParams(QuoteParams)
      const filters = yield* HttpServerRequest.schemaSearchParams(QuoteFilters)
      const sql = yield* SqlClient.SqlClient

      const lane = filters.lane ?? null
      const carrier = filters.carrier ?? null
      const ordering = ORDER_BY[filters.sort ?? "lane"]

      const lines = yield* sql<QuoteLine>`
        select lane_code, carrier_code, currency, base_cents, transit_days
        from rate_sheet_lines
        where sheet_id = ${sheetId}
          and org_id = ${principal.orgId}
          and withdrawn_at is null
          and (${lane}::text is null or lane_code like '%' || ${lane} || '%')
          and (${carrier}::text is null or carrier_code = ${carrier})
        order by ${sql.unsafe(ordering)}
        limit ${MAX_LINES}
      `

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
          HttpServerResponse.json({ error: "quote grid unavailable" }, { status: 502 })
      })
    )
  )
)
