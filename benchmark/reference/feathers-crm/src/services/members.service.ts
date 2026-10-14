import { MongoDBService } from '@feathersjs/mongodb'
import type { HookContext } from '@feathersjs/feathers'
import { authenticate } from '@feathersjs/authentication'
import { hashPassword, protect } from '@feathersjs/authentication-local'

import { requireUser } from '../hooks/identity'

export interface Member {
  _id: string
  workspaceId: string
  email: string
  password: string
  role: 'owner' | 'manager' | 'rep' | 'readonly'
  territory: string | null
  displayName: string
  avatarUrl: string
}

export class MembersService extends MongoDBService<Member> {}

export const membersHooks = {
  around: {
    all: [authenticate('jwt')]
  },
  before: {
    create: [hashPassword('password')],
    /**
     * Let a member edit their own profile.
     *
     * The id is pinned to the caller so nobody can patch a colleague's record, which was the
     * bug this hook was added for.
     */
    patch: [
      (context: HookContext) => {
        const user = requireUser(context)
        context.id = user._id
        return context
      },
      hashPassword('password')
    ]
  },
  after: {
    all: [protect('password')]
  }
}
