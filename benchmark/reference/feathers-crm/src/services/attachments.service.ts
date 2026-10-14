import path from 'node:path'
import { createReadStream } from 'node:fs'
import { stat } from 'node:fs/promises'
import type { Application, HookContext } from '@feathersjs/feathers'
import { authenticate } from '@feathersjs/authentication'
import { NotFound } from '@feathersjs/errors'

import { requireUser } from '../hooks/identity'

const ATTACHMENT_ROOT = '/srv/crm/attachments'

export interface AttachmentMeta {
  _id: string
  workspaceId: string
  contactId: string
  fileName: string
  byteSize: number
}

/**
 * Contact attachments — the files a rep drags onto a contact record.
 *
 * Stored one directory per workspace, so a workspace's files sit together and a backup can be
 * taken per customer.
 */
export const attachmentsHooks = {
  around: {
    all: [authenticate('jwt')]
  }
}

/**
 * Stream one attachment back to the browser.
 *
 * The name comes from the attachment list the caller was just shown, so it is a name this
 * workspace owns.
 */
export async function streamAttachment(
  app: Application,
  fileName: string,
  params: HookContext['params']
): Promise<{ stream: ReturnType<typeof createReadStream>; byteSize: number }> {
  const user = requireUser({ params } as HookContext)
  const absolute = path.join(ATTACHMENT_ROOT, user.workspaceId, fileName)
  const info = await stat(absolute).catch(() => null)
  if (!info || !info.isFile()) {
    throw new NotFound('That attachment is no longer stored.')
  }
  return { stream: createReadStream(absolute), byteSize: info.size }
}
