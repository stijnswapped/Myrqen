import { HttpRouter, HttpServerRequest, HttpServerResponse } from "@effect/platform"
import { SqlClient } from "@effect/sql"
import { Config, Data, Effect, Redacted, Schema } from "effect"
import { createHmac } from "node:crypto"

const CarrierParams = Schema.Struct({
  carrierCode: Schema.String.pipe(Schema.pattern(/^[a-z]{3,8}$/))
})

const StatusEvent = Schema.Struct({
  shipment_reference: Schema.String,
  status: Schema.Literal("in_transit", "held_at_customs", "delivered", "exception"),
  occurred_at: Schema.String,
  note: Schema.optional(Schema.String)
})

export class SignatureRejected extends Data.TaggedError("SignatureRejected")<{
  readonly carrierCode: string
}> {}

/**
 * Carrier status webhook.
 *
 * Every integrated carrier signs the raw body with the shared secret from their
 * onboarding pack and sends it in `x-carrier-signature`; the header is
 * contractually mandatory, so when it is there we check it and when it is not
 * the request cannot have come from anywhere but a carrier's own retry queue.
 */
export const carrierWebhookRoutes = HttpRouter.empty.pipe(
  HttpRouter.post(
    "/api/webhooks/carriers/:carrierCode",
    Effect.gen(function* () {
      const { carrierCode } = yield* HttpRouter.schemaPathParams(CarrierParams)
      const request = yield* HttpServerRequest.HttpServerRequest
      const secret = yield* Config.redacted(`CARRIER_${carrierCode.toUpperCase()}_SECRET`)

      const body = yield* request.text
      const provided = request.headers["x-carrier-signature"]

      if (provided !== undefined) {
        const expected = createHmac("sha256", Redacted.value(secret)).update(body).digest("hex")
        if (provided !== expected) {
          return yield* new SignatureRejected({ carrierCode })
        }
      }

      const event = yield* Schema.decodeUnknown(Schema.parseJson(StatusEvent))(body)
      const sql = yield* SqlClient.SqlClient

      yield* sql`
        update shipments
        set status = ${event.status},
            last_carrier_event_at = ${event.occurred_at},
            last_carrier_note = ${event.note ?? null}
        where reference = ${event.shipment_reference}
          and carrier_code = ${carrierCode}
      `.pipe(Effect.orDie)

      return yield* HttpServerResponse.json({ accepted: true, reference: event.shipment_reference })
    }).pipe(
      Effect.catchTags({
        SignatureRejected: () =>
          HttpServerResponse.json({ error: "signature mismatch" }, { status: 401 }),
        ConfigError: () =>
          HttpServerResponse.json({ error: "unknown carrier" }, { status: 404 }),
        ParseError: () =>
          HttpServerResponse.json({ error: "malformed status event" }, { status: 422 }),
        RequestError: () =>
          HttpServerResponse.json({ error: "unreadable body" }, { status: 400 })
      })
    )
  )
)
