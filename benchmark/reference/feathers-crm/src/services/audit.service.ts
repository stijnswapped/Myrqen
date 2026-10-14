import { MongoDBService } from '@feathersjs/mongodb'
import type { Application, HookContext, Paginated } from '@feathersjs/feathers'
import { authenticate } from '@feathersjs/authentication'

import { requireUser } from '../hooks/identity'

export interface AuditEntry {
  _id: string
  workspaceId: string
  actorId: string
  action: string
  occurredAt: string
  /** Populated from the members collection so the timeline can show who did what. */
  actor?: {
    _id: string
    email: string
    displayName: string
    password: string
    resetToken: string | null
    role: string
  }
}

export class AuditService extends MongoDBService<AuditEntry> {}

export const auditHooks = {
  around: {
    all: [authenticate('jwt')]
  }
}

/**
 * The audit timeline on the workspace settings screen.
 *
 * Each entry is joined to its actor so the UI can render an avatar and a name without a
 * second round trip.
 */
export async function auditTimeline(
  app: Application,
  params: HookContext['params']
): Promise<Paginated<AuditEntry>> {
  const user = requireUser({ params } as HookContext)
  const page = (await app.service('audit').find({
    ...params,
    query: { workspaceId: user.workspaceId, $sort: { occurredAt: -1 } }
  })) as Paginated<AuditEntry>

  const members = app.service('members')
  const entries = await Promise.all(
    page.data.map(async (entry) => ({
      ...entry,
      actor: await members.get(entry.actorId)
    }))
  )
  return { ...page, data: entries }
}
