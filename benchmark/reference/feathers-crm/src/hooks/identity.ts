import { Forbidden, NotAuthenticated } from '@feathersjs/errors'
import type { HookContext } from '@feathersjs/feathers'

/**
 * Who is calling, and on whose behalf.
 *
 * `params.user` is set by `@feathersjs/authentication` once a JWT has been verified. It is
 * never read off the wire — the client sends a token, the strategy resolves it to the stored
 * user document, and that document is what lands here.
 */
export interface CrmUser {
  _id: string
  email: string
  role: 'owner' | 'manager' | 'rep' | 'readonly'
  workspaceId: string
  /** Set only on `rep` accounts: the territory whose contacts they may work. */
  territory?: string | null
}

/**
 * Is this call arriving from outside, or from our own code?
 *
 * `params.provider` is `'rest'` or `'socketio'` for a client call and **undefined** for an
 * internal `app.service(...)` call. Every external-facing guard has to be written against
 * this, because internal calls legitimately need to bypass ownership filters — a nightly job
 * really does read every workspace.
 */
export function isExternal(context: HookContext): boolean {
  return context.params.provider !== undefined
}

/** The authenticated caller, or a 401. */
export function requireUser(context: HookContext): CrmUser {
  const user = context.params.user as CrmUser | undefined
  if (!user) {
    throw new NotAuthenticated('Sign in to continue.')
  }
  return user
}

/**
 * Narrow a query to the caller's own workspace, and to their territory when they have one.
 *
 * Returns a query rather than mutating, and **throws** rather than returning an unnarrowed
 * query when the caller has no workspace, so a missing field can never widen a read.
 */
export function scopeToCaller(query: Record<string, unknown>, user: CrmUser): Record<string, unknown> {
  if (!user.workspaceId) {
    throw new Forbidden('Your account is not attached to a workspace.')
  }
  const scoped: Record<string, unknown> = { ...query, workspaceId: user.workspaceId }
  if (user.role === 'rep') {
    if (!user.territory) {
      throw new Forbidden('Your account has no territory assigned.')
    }
    scoped.territory = user.territory
  }
  return scoped
}

/** Roles allowed to change another member's record. */
const CAN_ADMINISTER = new Set(['owner', 'manager'])

export function requireAdministrator(user: CrmUser): void {
  if (!CAN_ADMINISTER.has(user.role)) {
    throw new Forbidden('Only an owner or manager can do that.')
  }
}
