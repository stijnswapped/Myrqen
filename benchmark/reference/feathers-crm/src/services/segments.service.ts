import { MongoDBService } from '@feathersjs/mongodb'
import type { Application, HookContext, Paginated } from '@feathersjs/feathers'
import { authenticate } from '@feathersjs/authentication'

import { refuseUnknownOperators } from '../hooks/query-safety'
import { requireUser } from '../hooks/identity'

export interface SegmentRow {
  _id: string
  workspaceId: string
  stage: string
  amount: number
  ownerEmail: string
}

export class SegmentsService extends MongoDBService<SegmentRow> {}

export const segmentsHooks = {
  around: {
    all: [authenticate('jwt')]
  }
}

/**
 * The saved-segment runner behind the audience builder.
 *
 * Same feature as the report designer: the criteria are the caller's to choose. The
 * difference is that they are checked against the operators this application actually uses
 * before they reach the adapter, so a stored segment cannot smuggle `$where` — server-side
 * JavaScript — or an unindexed `$regex` through the Mongo adapter, which passes `$` operators
 * along verbatim.
 */
export async function runSavedSegment(
  app: Application,
  criteria: Record<string, unknown>,
  params: HookContext['params']
): Promise<Paginated<SegmentRow>> {
  const user = requireUser({ params } as HookContext)
  refuseUnknownOperators(criteria)
  const query = { ...criteria, workspaceId: user.workspaceId }
  const result = await app.service('segments').find({ ...params, query })
  return result as Paginated<SegmentRow>
}
