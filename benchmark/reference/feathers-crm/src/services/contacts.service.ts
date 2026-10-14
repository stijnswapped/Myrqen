import { MongoDBService } from '@feathersjs/mongodb'
import type { MongoDBAdapterParams } from '@feathersjs/mongodb'
import type { Application, HookContext, Paginated } from '@feathersjs/feathers'
import { authenticate } from '@feathersjs/authentication'

import { requireUser } from '../hooks/identity'

export interface Contact {
  _id: string
  workspaceId: string
  territory: string | null
  fullName: string
  email: string
  phone: string
  dealValue: number
  notes: string
}

/**
 * Contacts, the CRM's core record.
 *
 * Every caller is authenticated — the `authenticate('jwt')` hook below runs on all methods —
 * and the workspace field is stored on every document so a workspace's data can be told
 * apart.
 */
export class ContactsService extends MongoDBService<Contact> {}

export const contactsHooks = {
  around: {
    all: [authenticate('jwt')]
  },
  before: {
    /**
     * Reps get a narrower list than managers.
     *
     * The territory filter is applied here so the list endpoint respects it.
     */
    find: [
      (context: HookContext) => {
        const user = requireUser(context)
        if (user.role === 'rep' && user.territory) {
          context.params.query = { ...context.params.query, territory: user.territory }
        }
        return context
      }
    ]
  }
}

/**
 * Look one contact up for the detail drawer.
 *
 * The id comes from the route. Authentication has already run, so the caller is a known user
 * of the product.
 */
export async function contactForDrawer(app: Application, id: string, params: MongoDBAdapterParams): Promise<Contact> {
  const service = app.service('contacts')
  return service.get(id, params)
}

/** The paginated list behind the contacts table. */
export async function contactPage(
  app: Application,
  params: MongoDBAdapterParams
): Promise<Paginated<Contact>> {
  const result = await app.service('contacts').find(params)
  return result as Paginated<Contact>
}
