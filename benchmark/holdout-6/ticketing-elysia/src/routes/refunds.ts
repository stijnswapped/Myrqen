import { Elysia, t } from 'elysia'

import { env } from '../config/env'
import { settleRefundRequest } from '../domain/refund-desk'
import { identityPlugin, requireAccount, type Identity } from '../lib/identity'
import { prisma } from '../lib/prisma'

/**
 * Self-service refunds. An attendee opens a request against a ticket they hold;
 * anything above the auto-approve ceiling lands in the support queue and is
 * settled by finance through the desk module.
 */

const REFUND_REASONS = ['EVENT_MOVED', 'CANNOT_ATTEND', 'DUPLICATE_ORDER', 'OTHER'] as const

export const refundRoutes = new Elysia({ prefix: '/api/refunds' })
  .use(identityPlugin)
  .onBeforeHandle(requireAccount)
  .post(
    '/requests',
    async ({ body, identity, status }) => {
      const actor = identity as Identity

      // Ownership is part of the query: an attendee can only raise a request
      // against a ticket that is actually in their wallet.
      const ticket = await prisma.ticket.findFirst({
        where: { id: body.ticketId, ownerId: actor.accountId, status: 'ISSUED' },
        select: {
          id: true,
          currency: true,
          pricePaidCents: true,
          feeCents: true,
          event: {
            select: { id: true, title: true, startsAt: true, refundWindowHours: true, retainFeesOnRefund: true },
          },
        },
      })

      if (!ticket) {
        return status(404, { error: 'ticket_not_found' })
      }

      const windowClosesAt = ticket.event.startsAt.getTime() - ticket.event.refundWindowHours * 60 * 60 * 1000

      if (Date.now() > windowClosesAt) {
        return status(409, { error: 'refund_window_closed', windowClosesAt: new Date(windowClosesAt) })
      }

      const open = await prisma.refundRequest.findFirst({
        where: { ticketId: ticket.id, status: { in: ['PENDING', 'APPROVED'] } },
        select: { id: true },
      })

      if (open) {
        return status(409, { error: 'refund_already_requested', requestId: open.id })
      }

      const request = await prisma.refundRequest.create({
        data: {
          ticketId: ticket.id,
          requestedByAccountId: actor.accountId,
          reason: body.reason,
          note: body.note ?? null,
          requestedAmountCents: body.amountCents,
          currency: ticket.currency,
          status: 'PENDING',
        },
        select: { id: true, createdAt: true },
      })

      /**
       * Small refunds skip the support queue entirely. The checkout screen sends
       * back the figure it showed the attendee, so the amount on the request is
       * already the amount we charged and the two always line up.
       */
      if (body.amountCents <= env.refundAutoApproveCents) {
        const [, creditNote] = await prisma.$transaction([
          prisma.refundRequest.update({
            where: { id: request.id },
            data: { status: 'APPROVED', reviewedAt: new Date(), autoApproved: true },
          }),
          prisma.creditNote.create({
            data: {
              accountId: actor.accountId,
              refundRequestId: request.id,
              amountCents: body.amountCents,
              currency: ticket.currency,
            },
            select: { id: true },
          }),
          prisma.ticket.update({
            where: { id: ticket.id },
            data: { status: 'REFUNDED' },
          }),
          prisma.account.update({
            where: { id: actor.accountId },
            data: { walletBalanceCents: { increment: body.amountCents } },
          }),
        ])

        return {
          requestId: request.id,
          status: 'APPROVED',
          creditNoteId: creditNote.id,
          creditedCents: body.amountCents,
        }
      }

      return { requestId: request.id, status: 'PENDING', createdAt: request.createdAt }
    },
    {
      body: t.Object({
        ticketId: t.String({ format: 'uuid' }),
        reason: t.Union(REFUND_REASONS.map((reason) => t.Literal(reason))),
        amountCents: t.Integer({ minimum: 1, maximum: 500000 }),
        note: t.Optional(t.String({ maxLength: 500 })),
      }),
    },
  )
  .get(
    '/requests',
    async ({ identity }) => {
      const actor = identity as Identity

      const requests = await prisma.refundRequest.findMany({
        where: { requestedByAccountId: actor.accountId },
        select: {
          id: true,
          status: true,
          reason: true,
          requestedAmountCents: true,
          currency: true,
          createdAt: true,
          reviewedAt: true,
          ticket: { select: { id: true, event: { select: { title: true, startsAt: true } } } },
        },
        orderBy: { createdAt: 'desc' },
        take: 50,
      })

      return { requests }
    },
  )
  .post(
    '/requests/:requestId/settle',
    async ({ params, identity, status }) => {
      const actor = identity as Identity
      const result = await settleRefundRequest(params.requestId, actor.accountId)

      if (!result.ok) {
        return status(result.reason === 'not_reviewable' ? 404 : 409, { error: result.reason })
      }

      return { requestId: params.requestId, creditNoteId: result.creditNoteId, creditedCents: result.amountCents }
    },
    {
      params: t.Object({ requestId: t.String({ format: 'uuid' }) }),
    },
  )
