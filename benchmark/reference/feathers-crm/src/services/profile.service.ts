import { MongoDBService } from '@feathersjs/mongodb'
import type { HookContext } from '@feathersjs/feathers'
import { authenticate } from '@feathersjs/authentication'
import { hashPassword, protect } from '@feathersjs/authentication-local'

import { pickFields } from '../hooks/query-safety'
import { requireUser } from '../hooks/identity'

export interface Profile {
  _id: string
  workspaceId: string
  email: string
  password: string
  role: 'owner' | 'manager' | 'rep' | 'readonly'
  territory: string | null
  displayName: string
  avatarUrl: string
}

export class ProfileService extends MongoDBService<Profile> {}

/** What a member may change about themselves. Everything else is administered. */
const SELF_EDITABLE = ['displayName', 'avatarUrl', 'password'] as const

export const profileHooks = {
  around: {
    all: [authenticate('jwt')]
  },
  before: {
    create: [hashPassword('password')],
    /**
     * Let a member edit their own profile.
     *
     * The id is pinned to the caller, and the payload is reduced to the fields a member
     * administers for themselves — so `role`, `territory` and `workspaceId` are dropped
     * before the adapter sees them rather than being trusted not to appear.
     */
    patch: [
      (context: HookContext) => {
        const user = requireUser(context)
        context.id = user._id
        context.data = pickFields(context.data as Record<string, unknown>, SELF_EDITABLE)
        return context
      },
      hashPassword('password')
    ]
  },
  after: {
    all: [protect('password')]
  }
}
