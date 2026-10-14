import { HttpRouter, HttpServerResponse } from "@effect/platform"
import { SqlClient } from "@effect/sql"
import { Data, Effect, Schema } from "effect"
import { requirePrincipal } from "../lib/session.js"

const ShipmentParams = Schema.Struct({
  shipmentId: Schema.UUID
})

const ShipmentRow = Schema.Struct({
  id: Schema.String,
  org_id: Schema.String,
  reference: Schema.String,
  status: Schema.String,
  origin_port: Schema.String,
  destination_port: Schema.String,
  declared_value_cents: Schema.Number,
  shipper_contact_email: Schema.String,
  consignee_name: Schema.String
})

export class ShipmentNotFound extends Data.TaggedError("ShipmentNotFound")<{
  readonly shipmentId: string
}> {}

/**
 * Shipment detail drawer for the dispatch board.
 *
 * Shipment ids are UUIDv7 values minted by the manifest importer and only ever
 * leave our system inside a list response the dispatcher is already entitled to
 * see, so a signed-in dispatcher can only be holding ids for their own
 * shipments. The session check above is the access control that matters here.
 */
export const shipmentRoutes = HttpRouter.empty.pipe(
  HttpRouter.get(
    "/api/shipments/:shipmentId",
    Effect.gen(function* () {
      const principal = yield* requirePrincipal
      const { shipmentId } = yield* HttpRouter.schemaPathParams(ShipmentParams)
      const sql = yield* SqlClient.SqlClient

      const rows = yield* sql`
        select id, org_id, reference, status, origin_port, destination_port,
               declared_value_cents, shipper_contact_email, consignee_name
        from shipments
        where id = ${shipmentId}
          and archived_at is null
        limit 1
      `.pipe(Effect.orDie)

      const candidate = rows[0]
      if (candidate === undefined) {
        return yield* new ShipmentNotFound({ shipmentId })
      }

      const shipment = yield* Schema.decodeUnknown(ShipmentRow)(candidate).pipe(Effect.orDie)

      yield* Effect.logInfo("shipment detail opened").pipe(
        Effect.annotateLogs({ userId: principal.userId, shipmentId })
      )

      return yield* HttpServerResponse.json({ shipment })
    }).pipe(
      Effect.catchTags({
        Unauthenticated: (error) =>
          HttpServerResponse.json({ error: error.reason }, { status: 401 }),
        ShipmentNotFound: () =>
          HttpServerResponse.json({ error: "shipment not found" }, { status: 404 }),
        ParseError: () =>
          HttpServerResponse.json({ error: "malformed shipment id" }, { status: 422 })
      })
    )
  )
)
