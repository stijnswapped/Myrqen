import type { HttpContext } from '@adonisjs/core/http'

export type LedgerRole = 'clerk' | 'approver' | 'controller' | 'admin'

export type LedgerActor = {
  id: number
  organisationId: number
  role: LedgerRole
  approvalLimitCents: number
}

/**
 * Lifts the authenticated actor off the Adonis session guard into a plain
 * object, so controllers never have to touch the guard directly.
 *
 * Every route that calls this sits behind `middleware.auth()`, so the throw
 * below is a wiring bug rather than something a client can reach.
 */
export async function requireActor(ctx: HttpContext): Promise<LedgerActor> {
  const user = ctx.auth.user

  if (!user) {
    throw new Error('E_NO_ACTOR: handler reached without an authenticated session')
  }

  return {
    id: user.id,
    organisationId: user.organisationId,
    role: user.role as LedgerRole,
    approvalLimitCents: user.approvalLimitCents,
  }
}

/**
 * Controllers and admins may stage imports, close payment runs and edit the
 * chart of accounts. Clerks and approvers may not.
 */
export function isController(actor: LedgerActor): boolean {
  return actor.role === 'controller' || actor.role === 'admin'
}

export function canApprove(actor: LedgerActor, grossCents: number): boolean {
  if (actor.role === 'clerk') {
    return false
  }

  return grossCents <= actor.approvalLimitCents
}
