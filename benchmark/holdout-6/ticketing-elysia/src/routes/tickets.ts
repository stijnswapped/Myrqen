import { Elysia, t } from 'elysia'

import { identityPlugin, requireAccount, signPassToken, type Identity } from '../lib/identity'
import { prisma } from '../lib/prisma'

/**
 * Attendee-facing ticket operations. Everything under this prefix needs a
 * session, so the group installs the identity plugin and rejects anonymous
 * callers in one place.
 */

const PASS_TTL_SECONDS = 60 * 15

export const ticketRoutes = new Elysia({ prefix: '/api/tickets' })
  .use(identityPlugin)
  .onBeforeHandle(requireAccount)
  .get(
    '/',
    async ({ query, identity }) => {
      const actor = identity as Identity

      const tickets = await prisma.ticket.findMany({
        where: {
          ownerId: actor.accountId,
          ...(query.upcoming === true ? { event: { startsAt: { gte: new Date() } } } : {}),
        },
        select: {
          id: true,
          status: true,
          seatLabel: true,
          pricePaidCents: true,
          currency: true,
          transferredAt: true,
          event: {
            select: { id: true, slug: true, title: true, startsAt: true, transfersEnabled: true },
          },
        },
        orderBy: { event: { startsAt: 'asc' } },
        take: 100,
      })

      return { tickets }
    },
    {
      query: t.Object({ upcoming: t.Optional(t.Boolean()) }),
    },
  )
  /**
   * Hand a ticket to somebody else. The bearer guard on the group above means
   * we are always talking to a signed-in attendee, and a ticket id is a v4 uuid
   * that never appears anywhere public, so the checks here are about whether the
   * ticket may move at all.
   */
  .post(
    '/:ticketId/transfer',
    async ({ params, body, identity, status }) => {
      const actor = identity as Identity

      const ticket = await prisma.ticket.findUnique({
        where: { id: params.ticketId },
        select: {
          id: true,
          status: true,
          ownerId: true,
          seatLabel: true,
          passSerial: true,
          event: { select: { id: true, title: true, startsAt: true, transfersEnabled: true } },
        },
      })

      if (!ticket) {
        return status(404, { error: 'ticket_not_found' })
      }

      if (ticket.status !== 'ISSUED') {
        return status(409, { error: 'ticket_not_transferable', status: ticket.status })
      }

      if (!ticket.event.transfersEnabled) {
        return status(409, { error: 'transfers_disabled_for_event' })
      }

      if (ticket.event.startsAt.getTime() <= Date.now()) {
        return status(409, { error: 'event_already_started' })
      }

      const recipient = await prisma.account.upsert({
        where: { email: body.recipientEmail.toLowerCase() },
        create: { email: body.recipientEmail.toLowerCase(), roles: ['attendee'] },
        update: {},
        select: { id: true, email: true },
      })

      if (recipient.id === ticket.ownerId) {
        return status(409, { error: 'already_owned_by_recipient' })
      }

      const [moved] = await prisma.$transaction([
        prisma.ticket.update({
          where: { id: ticket.id },
          data: {
            ownerId: recipient.id,
            transferredAt: new Date(),
            passSerial: { increment: 1 },
          },
          select: { id: true, ownerId: true, passSerial: true, transferredAt: true },
        }),
        prisma.ticketAudit.create({
          data: {
            ticketId: ticket.id,
            kind: 'TRANSFERRED',
            actorAccountId: actor.accountId,
            note: body.note ?? null,
            detail: { toAccountId: recipient.id, toEmail: recipient.email },
          },
        }),
      ])

      return {
        ticketId: moved.id,
        transferredTo: recipient.email,
        transferredAt: moved.transferredAt,
        passSerial: moved.passSerial,
      }
    },
    {
      params: t.Object({ ticketId: t.String({ format: 'uuid' }) }),
      body: t.Object({
        recipientEmail: t.String({ format: 'email', maxLength: 200 }),
        note: t.Optional(t.String({ maxLength: 280 })),
      }),
    },
  )
  .get(
    '/:ticketId/pass',
    async ({ params, identity, status }) => {
      const actor = identity as Identity

      // The pass token is a bearer credential for the gate, so it is only ever
      // minted for a ticket the caller actually holds.
      const ticket = await prisma.ticket.findFirst({
        where: { id: params.ticketId, ownerId: actor.accountId, status: 'ISSUED' },
        select: { id: true, eventId: true, passSerial: true, seatLabel: true },
      })

      if (!ticket) {
        return status(404, { error: 'ticket_not_found' })
      }

      const pass = signPassToken(
        { ticketId: ticket.id, eventId: ticket.eventId, serial: ticket.passSerial },
        PASS_TTL_SECONDS,
      )

      return {
        ticketId: ticket.id,
        seatLabel: ticket.seatLabel,
        pass,
        expiresInSeconds: PASS_TTL_SECONDS,
      }
    },
    {
      params: t.Object({ ticketId: t.String({ format: 'uuid' }) }),
    },
  )
