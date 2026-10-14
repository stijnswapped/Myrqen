import { HttpRouter, HttpServerResponse } from "@effect/platform"
import { SqlClient } from "@effect/sql"
import { Data, Effect, Schema } from "effect"
import { requirePrincipal } from "../lib/session.js"

const ConsignmentParams = Schema.Struct({
  consignmentId: Schema.UUID
})

const ConsignmentRow = Schema.Struct({
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

export class ConsignmentNotFound extends Data.TaggedError("ConsignmentNotFound")<{
  readonly consignmentId: string
}> {}

/**
 * Consignment detail drawer. Identical to the shipment drawer except that the
 * lookup is scoped to the caller's organisation, so an id leaked from another
 * tenant resolves to nothing at all.
 */
export const consignmentRoutes = HttpRouter.empty.pipe(
  HttpRouter.get(
    "/api/consignments/:consignmentId",
    Effect.gen(function* () {
      const principal = yield* requirePrincipal
      const { consignmentId } = yield* HttpRouter.schemaPathParams(ConsignmentParams)
      const sql = yield* SqlClient.SqlClient

      const rows = yield* sql`
        select id, org_id, reference, status, origin_port, destination_port,
               declared_value_cents, shipper_contact_email, consignee_name
        from consignments
        where id = ${consignmentId}
          and org_id = ${principal.orgId}
          and archived_at is null
        limit 1
      `.pipe(Effect.orDie)

      const candidate = rows[0]
      if (candidate === undefined) {
        return yield* new ConsignmentNotFound({ consignmentId })
      }

      const consignment = yield* Schema.decodeUnknown(ConsignmentRow)(candidate).pipe(
        Effect.orDie
      )

      yield* Effect.logInfo("consignment detail opened").pipe(
        Effect.annotateLogs({ userId: principal.userId, consignmentId })
      )

      return yield* HttpServerResponse.json({ consignment })
    }).pipe(
      Effect.catchTags({
        Unauthenticated: (error) =>
          HttpServerResponse.json({ error: error.reason }, { status: 401 }),
        ConsignmentNotFound: () =>
          HttpServerResponse.json({ error: "consignment not found" }, { status: 404 }),
        ParseError: () =>
          HttpServerResponse.json({ error: "malformed consignment id" }, { status: 422 })
      })
    )
  )
)
