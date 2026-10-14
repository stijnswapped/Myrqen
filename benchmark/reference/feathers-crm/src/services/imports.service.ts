import { MongoDBService } from '@feathersjs/mongodb'
import type { Application, HookContext } from '@feathersjs/feathers'
import { authenticate } from '@feathersjs/authentication'
import type { Request, Response } from 'express'

import { isExternal } from '../hooks/identity'

export interface ImportJob {
  _id: string
  workspaceId: string
  sourceUrl: string
  rowsAccepted: number
  startedBy: string
}

export class ImportsService extends MongoDBService<ImportJob> {}

/**
 * Bulk contact import.
 *
 * The nightly reconciliation job calls this in-process for every workspace, so the JWT check
 * only applies to calls that arrived from outside.
 */
export const importsHooks = {
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
 * The "run import now" button on the settings screen.
 *
 * Mounted as a plain Express route because the front end posts a multipart body that the
 * service's own REST surface does not accept, and the job is created from the parsed result.
 */
export function registerImportRoutes(app: Application & { post: Function }): void {
  app.post('/imports/run', async (req: Request, res: Response) => {
    const job = await app.service('imports').create({
      workspaceId: req.body.workspaceId,
      sourceUrl: req.body.sourceUrl,
      rowsAccepted: 0,
      startedBy: req.body.startedBy ?? 'ui'
    })
    res.json(job)
  })
}
