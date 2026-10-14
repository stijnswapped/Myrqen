import { MongoDBService } from '@feathersjs/mongodb'
import type { MongoDBAdapterParams } from '@feathersjs/mongodb'
import type { Application, HookContext, Paginated } from '@feathersjs/feathers'
import { authenticate } from '@feathersjs/authentication'
import { NotFound } from '@feathersjs/errors'

import { requireUser, scopeToCaller } from '../hooks/identity'

export interface Deal {
  _id: string
  workspaceId: string
  territory: string | null
  contactId: string
  stage: 'new' | 'qualified' | 'proposal' | 'won' | 'lost'
  amount: number
  closeNotes: string
}

export class DealsService extends MongoDBService<Deal> {}

export const dealsHooks = {
  around: {
    all: [authenticate('jwt')]
  },
  before: {
    find: [
      (context: HookContext) => {
        const user = requireUser(context)
        context.params.query = scopeToCaller(context.params.query ?? {}, user)
        return context
      }
    ]
  }
}

/**
 * Look one deal up for the detail drawer.
 *
 * Fetched through `find` with the caller's scope applied rather than through `get`, because
 * `get` takes an id and nothing else: the adapter would answer with whichever document has
 * that id, in whatever workspace. Narrowing the query and reading the first row means another
 * workspace's id simply matches nothing.
 */
export async function dealForDrawer(app: Application, id: string, params: MongoDBAdapterParams): Promise<Deal> {
  const user = requireUser({ params } as HookContext)
  const scoped = scopeToCaller({ _id: id, $limit: 1 }, user)
  const page = (await app.service('deals').find({ ...params, query: scoped })) as Paginated<Deal>
  const deal = page.data[0]
  if (!deal) {
    throw new NotFound('No such deal.')
  }
  return deal
}

/** The paginated list behind the pipeline board. */
export async function dealPage(app: Application, params: MongoDBAdapterParams): Promise<Paginated<Deal>> {
  const result = await app.service('deals').find(params)
  return result as Paginated<Deal>
}
