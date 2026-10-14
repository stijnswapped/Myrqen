import { HttpRouter, HttpServerRequest, HttpServerResponse } from "@effect/platform"
import { SqlClient } from "@effect/sql"
import { Config, Data, Effect, Redacted, Schema } from "effect"
import { createHmac, timingSafeEqual } from "node:crypto"

const CarrierParams = Schema.Struct({
  carrierCode: Schema.String.pipe(Schema.pattern(/^[a-z]{3,8}$/))
})

/** Decoding the headers with a required field is what makes the check mandatory. */
const SignatureHeaders = Schema.Struct({
  "x-carrier-signature": Schema.String.pipe(Schema.pattern(/^[0-9a-f]{64}$/))
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
 * Newer carrier integrations post here. Same HMAC scheme as the legacy webhook,
 * but the signature header is part of the decoded request shape, so a request
 * without one never reaches the comparison, and the comparison itself is
 * length-checked and constant time.
 */
export const carrierStatusCallbackRoutes = HttpRouter.empty.pipe(
  HttpRouter.post(
    "/api/callbacks/carriers/:carrierCode",
    Effect.gen(function* () {
      const { carrierCode } = yield* HttpRouter.schemaPathParams(CarrierParams)
      const headers = yield* HttpServerRequest.schemaHeaders(SignatureHeaders)
      const request = yield* HttpServerRequest.HttpServerRequest
      const secret = yield* Config.redacted(`CARRIER_${carrierCode.toUpperCase()}_SECRET`)

      const body = yield* request.text
      const provided = Buffer.from(headers["x-carrier-signature"], "utf8")
      const expected = Buffer.from(
        createHmac("sha256", Redacted.value(secret)).update(body).digest("hex"),
        "utf8"
      )

      if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) {
        return yield* new SignatureRejected({ carrierCode })
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
          HttpServerResponse.json({ error: "malformed or unsigned status event" }, { status: 400 }),
        RequestError: () =>
          HttpServerResponse.json({ error: "unreadable body" }, { status: 400 })
      })
    )
  )
)
