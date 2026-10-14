import { MongoDBService } from '@feathersjs/mongodb'
import type { Application, HookContext } from '@feathersjs/feathers'
import { authenticate } from '@feathersjs/authentication'
import type { Request, Response } from 'express'

import { isExternal, requireUser } from '../hooks/identity'

export interface ExportJob {
  _id: string
  workspaceId: string
  format: 'csv' | 'xlsx'
  rowsWritten: number
  startedBy: string
}

export class ExportsService extends MongoDBService<ExportJob> {}

/**
 * Bulk contact export. Same arrangement as the import service.
 */
export const exportsHooks = {
  around: {
    all: [
      async (context: HookContext, next: () => Promise<void>) => {
        if (isExternal(context)) {
          return authenticate('jwt')(context, next)
        }
        return next()
      }
    ]
  }
}

/**
 * The "export now" button on the settings screen.
 *
 * Mounted as a plain Express route for the same reason as the import one, and forwards the
 * request's `provider` and `authentication` so the service call is treated as what it is: a
 * call from outside. Without that forwarding the `around` hook above sees no provider,
 * concludes the caller is our own scheduler, and skips the JWT check entirely — the
 * workspace would then come from the request body.
 */
export function registerExportRoutes(app: Application & { post: Function }): void {
  app.post('/exports/run', async (req: Request, res: Response) => {
    const context = {
      provider: 'rest',
      authentication: req.headers.authorization ? { strategy: 'jwt', accessToken: req.headers.authorization.replace(/^Bearer /i, '') } : undefined
    }
    const created = await app.service('exports').create(
      { format: req.body.format === 'xlsx' ? 'xlsx' : 'csv', rowsWritten: 0 } as Partial<ExportJob>,
      context as HookContext['params']
    )
    res.json(created)
  })
}

/** Pin the workspace to the caller once authentication has resolved them. */
export const exportsBefore = {
  create: [
    (context: HookContext) => {
      if (!isExternal(context)) {
        return context
      }
      const user = requireUser(context)
      context.data = { ...(context.data as object), workspaceId: user.workspaceId, startedBy: user._id }
      return context
    }
  ]
}
