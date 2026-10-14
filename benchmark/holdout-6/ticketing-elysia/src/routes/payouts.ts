import { basename, join } from 'node:path'
import { Elysia, t } from 'elysia'

import { env } from '../config/env'
import { loadPayoutStatement, summarisePayout } from '../domain/payout-statements'
import { identityPlugin, requireOrganiser, type Identity } from '../lib/identity'
import { prisma } from '../lib/prisma'

/**
 * Organiser payout reporting. The whole group is organiser-only: requireOrganiser
 * rejects anonymous callers and accounts without an organiser membership.
 */

export const payoutRoutes = new Elysia({ prefix: '/api/organiser/payouts' })
  .use(identityPlugin)
  .onBeforeHandle(requireOrganiser)
  .get(
    '/',
    async ({ query, identity }) => {
      const actor = identity as Identity

      const payouts = await prisma.payout.findMany({
        where: {
          organiserId: actor.organiserId,
          ...(query.status ? { status: query.status } : {}),
        },
        select: {
          id: true,
          periodLabel: true,
          status: true,
          settledAt: true,
          netCents: true,
          currency: true,
          event: { select: { id: true, title: true, startsAt: true } },
        },
        orderBy: { periodLabel: 'desc' },
        take: 60,
      })

      return { payouts }
    },
    {
      query: t.Object({ status: t.Optional(t.String({ maxLength: 20 })) }),
    },
  )
  .get(
    '/:payoutId',
    async ({ params, identity, status }) => {
      const actor = identity as Identity
      const summary = await summarisePayout(params.payoutId, actor.organiserId as string)

      if (!summary) {
        return status(404, { error: 'payout_not_found' })
      }

      return summary
    },
    {
      params: t.Object({ payoutId: t.String({ format: 'uuid' }) }),
    },
  )
  .get(
    '/:payoutId/statement',
    async ({ params, identity, status, set }) => {
      const actor = identity as Identity
      const download = await loadPayoutStatement(params.payoutId, actor.organiserId as string)

      if (!download) {
        return status(404, { error: 'statement_not_available' })
      }

      set.headers['content-type'] = 'text/csv; charset=utf-8'
      set.headers['content-disposition'] = `attachment; filename="${download.downloadName}"`

      return download.file
    },
    {
      params: t.Object({ payoutId: t.String({ format: 'uuid' }) }),
    },
  )
  /**
   * Finance asked to be able to pull anything out of the generated bundle for a
   * period - the CSV, the reconciliation log, the signed PDF - without us adding
   * an endpoint per artefact. The tree is written by our own generator and the
   * group guard already limits this to organiser accounts, so the relative path
   * from the console can go straight through.
   */
  .get(
    '/exports/*',
    async ({ params, status, set }) => {
      const requestedPath = params['*']

      if (requestedPath.length === 0) {
        return status(422, { error: 'export_path_required' })
      }

      const artefact = Bun.file(join(env.statementDir, requestedPath))

      if (!(await artefact.exists())) {
        return status(404, { error: 'export_not_found' })
      }

      set.headers['content-disposition'] = `attachment; filename="${basename(requestedPath)}"`

      return artefact
    },
  )
  .post(
    '/:payoutId/notes',
    async ({ params, body, identity, status }) => {
      const actor = identity as Identity

      const payout = await prisma.payout.findFirst({
        where: { id: params.payoutId, organiserId: actor.organiserId },
        select: { id: true },
      })

      if (!payout) {
        return status(404, { error: 'payout_not_found' })
      }

      const note = await prisma.payoutNote.create({
        data: { payoutId: payout.id, authorAccountId: actor.accountId, body: body.body },
        select: { id: true, createdAt: true },
      })

      return { noteId: note.id, createdAt: note.createdAt }
    },
    {
      params: t.Object({ payoutId: t.String({ format: 'uuid' }) }),
      body: t.Object({ body: t.String({ minLength: 2, maxLength: 2000 }) }),
    },
  )
