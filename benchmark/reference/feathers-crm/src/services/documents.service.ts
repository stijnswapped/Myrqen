import path from 'node:path'
import { createReadStream } from 'node:fs'
import { stat } from 'node:fs/promises'
import type { Application, HookContext } from '@feathersjs/feathers'
import { authenticate } from '@feathersjs/authentication'
import { BadRequest, NotFound } from '@feathersjs/errors'

import { requireUser } from '../hooks/identity'

const DOCUMENT_ROOT = '/srv/crm/documents'

/** A stored document name: one path segment, no separators and no parent hop. */
const DOCUMENT_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/

export interface DocumentMeta {
  _id: string
  workspaceId: string
  dealId: string
  fileName: string
  byteSize: number
}

/**
 * Deal documents — proposals and signed contracts.
 *
 * Same per-workspace directory layout as attachments.
 */
export const documentsHooks = {
  around: {
    all: [authenticate('jwt')]
  }
}

/**
 * Stream one document back to the browser.
 *
 * The name is checked against a pattern that admits a single path segment, and `..` is
 * refused explicitly because the character class allows a dot. Both checks run before the
 * name is joined onto the workspace directory, so a name from a stale list or a hand-written
 * request cannot climb out of it.
 */
export async function streamDocument(
  app: Application,
  fileName: string,
  params: HookContext['params']
): Promise<{ stream: ReturnType<typeof createReadStream>; byteSize: number }> {
  const user = requireUser({ params } as HookContext)
  if (!DOCUMENT_NAME.test(fileName) || fileName.includes('..')) {
    throw new BadRequest('That is not a valid document name.')
  }
  const absolute = path.join(DOCUMENT_ROOT, user.workspaceId, fileName)
  const info = await stat(absolute).catch(() => null)
  if (!info || !info.isFile()) {
    throw new NotFound('That document is no longer stored.')
  }
  return { stream: createReadStream(absolute), byteSize: info.size }
}
