import { HttpServerRequest } from "@effect/platform"
import { Config, Context, Data, Effect, Layer, Redacted } from "effect"
import jwt from "jsonwebtoken"

export interface DriverIdentity {
  readonly driverId: string
  readonly orgId: string
  readonly scopes: ReadonlyArray<string>
}

export class DriverTokenRejected extends Data.TaggedError("DriverTokenRejected")<{
  readonly reason: string
}> {}

export class DriverPrincipal extends Context.Tag("app/DriverPrincipal")<
  DriverPrincipal,
  DriverIdentity
>() {}

const BEARER = "Bearer "
const ISSUER = "https://portal.northgatefreight.example"
const AUDIENCE = "northgate-driver-api"

/**
 * The driver handheld app authenticates with a JWT from the same portal as the
 * partner integrations. The signature is checked here against the portal key,
 * with the algorithm pinned so a token cannot arrive claiming "none", and the
 * issuer and audience pinned so a token minted for another service is refused.
 */
export const resolveDriverIdentity = Effect.gen(function* () {
  const request = yield* HttpServerRequest.HttpServerRequest
  const signingKey = yield* Config.redacted("DRIVER_JWT_PUBLIC_KEY")
  const header = request.headers["authorization"]

  if (header === undefined || !header.startsWith(BEARER)) {
    return yield* new DriverTokenRejected({ reason: "missing bearer token" })
  }

  const claims = yield* Effect.try({
    try: () =>
      jwt.verify(header.slice(BEARER.length), Redacted.value(signingKey), {
        algorithms: ["RS256"],
        issuer: ISSUER,
        audience: AUDIENCE,
        clockTolerance: 5
      }),
    catch: () => new DriverTokenRejected({ reason: "signature rejected" })
  })

  if (typeof claims === "string") {
    return yield* new DriverTokenRejected({ reason: "unreadable token" })
  }
  if (typeof claims.org_id !== "string" || typeof claims.sub !== "string") {
    return yield* new DriverTokenRejected({ reason: "incomplete claims" })
  }

  return {
    driverId: claims.sub,
    orgId: claims.org_id,
    scopes: Array.isArray(claims.scopes) ? claims.scopes.map(String) : []
  } satisfies DriverIdentity
})

/** Attached per request by the handheld router. */
export const DriverPrincipalLive = Layer.effect(DriverPrincipal, resolveDriverIdentity)

export const requireScope = (identity: DriverIdentity, scope: string) =>
  identity.scopes.includes(scope)
    ? Effect.void
    : new DriverTokenRejected({ reason: `missing scope ${scope}` })
