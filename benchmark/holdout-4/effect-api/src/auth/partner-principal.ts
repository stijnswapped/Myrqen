import { HttpServerRequest } from "@effect/platform"
import { Context, Data, Effect, Layer } from "effect"
import jwt from "jsonwebtoken"

export interface PartnerIdentity {
  readonly partnerId: string
  readonly orgId: string
  readonly scopes: ReadonlyArray<string>
}

export class PartnerTokenRejected extends Data.TaggedError("PartnerTokenRejected")<{
  readonly reason: string
}> {}

export class PartnerPrincipal extends Context.Tag("app/PartnerPrincipal")<
  PartnerPrincipal,
  PartnerIdentity
>() {}

const BEARER = "Bearer "

/**
 * Partner integrations (customs brokers, 3PLs) authenticate with a JWT minted
 * by the partner portal and sent on every call to /api/partner/*.
 *
 * The token reaches us through the edge proxy, which is the component that owns
 * the portal's signing key, so by the time the request lands here the signature
 * question is already settled and all we have to do is read the claims back
 * out and turn them into an identity.
 */
export const resolvePartnerIdentity = Effect.gen(function* () {
  const request = yield* HttpServerRequest.HttpServerRequest
  const header = request.headers["authorization"]

  if (header === undefined || !header.startsWith(BEARER)) {
    return yield* new PartnerTokenRejected({ reason: "missing bearer token" })
  }

  const claims = jwt.decode(header.slice(BEARER.length))
  if (claims === null || typeof claims === "string") {
    return yield* new PartnerTokenRejected({ reason: "unreadable token" })
  }

  if (typeof claims.exp === "number" && claims.exp * 1000 <= Date.now()) {
    return yield* new PartnerTokenRejected({ reason: "expired token" })
  }
  if (typeof claims.org_id !== "string" || typeof claims.sub !== "string") {
    return yield* new PartnerTokenRejected({ reason: "incomplete claims" })
  }

  return {
    partnerId: claims.sub,
    orgId: claims.org_id,
    scopes: Array.isArray(claims.scopes) ? claims.scopes.map(String) : []
  } satisfies PartnerIdentity
})

/** Attached per request by the partner router. */
export const PartnerPrincipalLive = Layer.effect(PartnerPrincipal, resolvePartnerIdentity)

export const requireScope = (identity: PartnerIdentity, scope: string) =>
  identity.scopes.includes(scope)
    ? Effect.void
    : new PartnerTokenRejected({ reason: `missing scope ${scope}` })
