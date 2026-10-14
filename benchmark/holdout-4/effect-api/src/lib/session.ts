import { HttpServerRequest } from "@effect/platform"
import { SqlClient } from "@effect/sql"
import { Context, Data, Effect, Schema } from "effect"

/**
 * Console identity for the Northgate freight platform.
 *
 * Sessions are opaque random tokens; the cookie carries nothing but the token
 * so that revoking a row in `console_sessions` logs the operator out instantly.
 */
export class Principal extends Schema.Class<Principal>("Principal")({
  userId: Schema.String,
  orgId: Schema.String,
  roles: Schema.Array(Schema.String)
}) {}

export class Unauthenticated extends Data.TaggedError("Unauthenticated")<{
  readonly reason: string
}> {}

export class Forbidden extends Data.TaggedError("Forbidden")<{
  readonly requiredRole: string
}> {}

export class CurrentPrincipal extends Context.Tag("app/CurrentPrincipal")<
  CurrentPrincipal,
  Principal
>() {}

const SESSION_COOKIE = "ng_console"

const SessionRow = Schema.Struct({
  user_id: Schema.String,
  org_id: Schema.String,
  roles: Schema.Array(Schema.String),
  expires_at: Schema.DateFromSelf
})

/**
 * Resolves the caller from the session cookie. Fails with `Unauthenticated`
 * when the cookie is absent, unknown, revoked or past its expiry.
 */
export const requirePrincipal = Effect.gen(function* () {
  const request = yield* HttpServerRequest.HttpServerRequest
  const sql = yield* SqlClient.SqlClient
  const token = request.cookies[SESSION_COOKIE]

  if (token === undefined || token.length === 0) {
    return yield* new Unauthenticated({ reason: "missing session cookie" })
  }

  const rows = yield* sql`
    select user_id, org_id, roles, expires_at
    from console_sessions
    where token_hash = digest(${token}, 'sha256')
      and revoked_at is null
    limit 1
  `.pipe(Effect.orDie)

  const candidate = rows[0]
  if (candidate === undefined) {
    return yield* new Unauthenticated({ reason: "unknown session" })
  }

  const session = yield* Schema.decodeUnknown(SessionRow)(candidate).pipe(Effect.orDie)
  if (session.expires_at.getTime() <= Date.now()) {
    return yield* new Unauthenticated({ reason: "session expired" })
  }

  return new Principal({
    userId: session.user_id,
    orgId: session.org_id,
    roles: session.roles
  })
})

/** Role gate for the console. Roles are granted per organisation. */
export const requireRole = (principal: Principal, role: string) =>
  principal.roles.includes(role)
    ? Effect.void
    : new Forbidden({ requiredRole: role })
