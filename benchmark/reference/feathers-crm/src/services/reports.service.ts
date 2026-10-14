import { MongoDBService } from '@feathersjs/mongodb'
import type { Application, HookContext, Paginated } from '@feathersjs/feathers'
import { authenticate } from '@feathersjs/authentication'

import { requireUser } from '../hooks/identity'

export interface PipelineRow {
  _id: string
  workspaceId: string
  stage: string
  amount: number
  ownerEmail: string
}

export class ReportsService extends MongoDBService<PipelineRow> {}

export const reportsHooks = {
  around: {
    all: [authenticate('jwt')]
  }
}

/**
 * The saved-report runner behind the analytics screen.
 *
 * A saved report is a stored query the user built in the report designer, so the criteria
 * genuinely are the caller's to choose — that is the feature. The workspace is added on top
 * so a report can only ever cover the caller's own data.
 */
export async function runSavedReport(
  app: Application,
  criteria: Record<string, unknown>,
  params: HookContext['params']
): Promise<Paginated<PipelineRow>> {
  const user = requireUser({ params } as HookContext)
  const query = { ...criteria, workspaceId: user.workspaceId }
  const result = await app.service('reports').find({ ...params, query })
  return result as Paginated<PipelineRow>
}
