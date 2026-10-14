import { Elysia, t } from 'elysia'

import { identityPlugin, requireAccount, type Identity } from '../lib/identity'
import { prisma } from '../lib/prisma'

/**
 * The wallet is the attendee's own view of what they are holding: group
 * bookings, seat labels and the name printed on each pass. Every write in here
 * is scoped to the caller's own rows.
 */

export const walletRoutes = new Elysia({ prefix: '/api/wallet' })
  .use(identityPlugin)
  .onBeforeHandle(requireAccount)
  .get(
    '/tickets/:ticketId',
    async ({ params, identity, status }) => {
      const actor = identity as Identity

      const ticket = await prisma.ticket.findFirst({
        where: { id: params.ticketId, ownerId: actor.accountId },
        select: {
          id: true,
          status: true,
          seatLabel: true,
          holderName: true,
          holderEmail: true,
          pricePaidCents: true,
          currency: true,
          event: { select: { id: true, title: true, startsAt: true, doorsAt: true } },
        },
      })

      if (!ticket) {
        return status(404, { error: 'ticket_not_found' })
      }

      return ticket
    },
    {
      params: t.Object({ ticketId: t.String({ format: 'uuid' }) }),
    },
  )
  /**
   * Re-point a ticket from a group booking at a different guest. The owner
   * predicate lives in the where clause, so a ticket belonging to somebody else
   * simply does not match and the update touches nothing.
   */
  .patch(
    '/tickets/:ticketId/holder',
    async ({ params, body, identity, status }) => {
      const actor = identity as Identity

      const changed = await prisma.ticket.updateMany({
        where: {
          id: params.ticketId,
          ownerId: actor.accountId,
          status: 'ISSUED',
          event: { startsAt: { gte: new Date() } },
        },
        data: {
          holderName: body.holderName,
          holderEmail: body.holderEmail.toLowerCase(),
          passSerial: { increment: 1 },
        },
      })

      if (changed.count === 0) {
        return status(404, { error: 'ticket_not_found' })
      }

      await prisma.ticketAudit.create({
        data: {
          ticketId: params.ticketId,
          kind: 'HOLDER_CHANGED',
          actorAccountId: actor.accountId,
          detail: { holderEmail: body.holderEmail.toLowerCase() },
        },
      })

      return { ticketId: params.ticketId, holderName: body.holderName, holderEmail: body.holderEmail.toLowerCase() }
    },
    {
      params: t.Object({ ticketId: t.String({ format: 'uuid' }) }),
      body: t.Object({
        holderName: t.String({ minLength: 2, maxLength: 120 }),
        holderEmail: t.String({ format: 'email', maxLength: 200 }),
      }),
    },
  )
  .get(
    '/credit-notes',
    async ({ identity }) => {
      const actor = identity as Identity

      const notes = await prisma.creditNote.findMany({
        where: { accountId: actor.accountId },
        select: { id: true, amountCents: true, currency: true, issuedAt: true, refundRequestId: true },
        orderBy: { issuedAt: 'desc' },
        take: 50,
      })

      return {
        balanceCents: notes.reduce((total, note) => total + note.amountCents, 0),
        notes,
      }
    },
  )
