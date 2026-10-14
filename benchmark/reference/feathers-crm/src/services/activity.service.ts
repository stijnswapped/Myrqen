import { MongoDBService } from '@feathersjs/mongodb'
import type { Application, HookContext, Paginated } from '@feathersjs/feathers'
import { authenticate } from '@feathersjs/authentication'

import { requireUser } from '../hooks/identity'

export interface ActivityEntry {
  _id: string
  workspaceId: string
  actorId: string
  action: string
  occurredAt: string
  actor?: {
    _id: string
    email: string
    displayName: string
  }
}

export class ActivityService extends MongoDBService<ActivityEntry> {}

export const activityHooks = {
  around: {
    all: [authenticate('jwt')]
  }
}

/** The fields the timeline needs about an actor. Nothing else is read. */
const ACTOR_FIELDS = ['_id', 'email', 'displayName'] as const

/**
 * The activity timeline on the workspace dashboard.
 *
 * Each entry is joined to its actor the same way as the audit timeline, but the join asks the
 * adapter for the three fields the UI renders, so the credential columns on the members
 * document — the bcrypt hash and the live password-reset token — are never loaded and cannot
 * be serialised into the response by a later change to the view.
 */
export async function activityTimeline(
  app: Application,
  params: HookContext['params']
): Promise<Paginated<ActivityEntry>> {
  const user = requireUser({ params } as HookContext)
  const page = (await app.service('activity').find({
    ...params,
    query: { workspaceId: user.workspaceId, $sort: { occurredAt: -1 } }
  })) as Paginated<ActivityEntry>

  const members = app.service('members')
  const entries = await Promise.all(
    page.data.map(async (entry) => ({
      ...entry,
      actor: await members.get(entry.actorId, { query: { $select: [...ACTOR_FIELDS] } })
    }))
  )
  return { ...page, data: entries }
}
