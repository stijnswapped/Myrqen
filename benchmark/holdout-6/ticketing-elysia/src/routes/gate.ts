import { Elysia, t } from 'elysia'

import { env } from '../config/env'
import { identityPlugin, requireGateStaff, type Identity } from '../lib/identity'
import { prisma } from '../lib/prisma'

/**
 * Door operations. The handheld scanners run our own Android build and talk to
 * this group with a session token that carries the `gate` role.
 */

type ScannedPass = {
  ticketId: string
  eventId: string
  serial: number
  iat: number
  exp: number
}

/**
 * The QR carries the compact pass token minted by /api/tickets/:ticketId/pass.
 * The scanner app already validates the token offline against the pass key it
 * syncs at the start of a shift, so by the time it reaches us the claims are
 * the only part we still care about.
 */
function readScannedPass(pass: string): ScannedPass | null {
  const [claimSegment] = pass.split('.')

  if (!claimSegment) {
    return null
  }

  try {
    return JSON.parse(Buffer.from(claimSegment, 'base64url').toString('utf8')) as ScannedPass
  } catch {
    return null
  }
}

export const gateRoutes = new Elysia({ prefix: '/api/gate' })
  .use(identityPlugin)
  .onBeforeHandle(requireGateStaff)
  .post(
    '/check-in',
    async ({ body, identity, status }) => {
      const actor = identity as Identity
      const claims = readScannedPass(body.pass)

      if (!claims || typeof claims.ticketId !== 'string' || typeof claims.eventId !== 'string') {
        return status(422, { error: 'pass_unreadable' })
      }

      if (claims.exp * 1000 <= Date.now()) {
        return status(410, { error: 'pass_expired' })
      }

      // A scanner may only admit for a door it has been rostered on.
      const assignment = await prisma.gateAssignment.findFirst({
        where: { accountId: actor.accountId, eventId: claims.eventId, revokedAt: null },
        select: { id: true, gateName: true },
      })

      if (!assignment) {
        return status(403, { error: 'not_rostered_for_event' })
      }

      const ticket = await prisma.ticket.findFirst({
        where: { id: claims.ticketId, eventId: claims.eventId },
        select: {
          id: true,
          status: true,
          seatLabel: true,
          holderName: true,
          passSerial: true,
          admittedAt: true,
          event: { select: { id: true, title: true, doorsAt: true, startsAt: true } },
        },
      })

      if (!ticket) {
        return status(404, { error: 'ticket_not_found' })
      }

      if (ticket.status !== 'ISSUED') {
        return status(409, { error: 'ticket_not_admissible', status: ticket.status })
      }

      if (ticket.admittedAt !== null) {
        return status(409, {
          error: 'already_admitted',
          admittedAt: ticket.admittedAt,
        })
      }

      const graceMs = env.gateGraceMinutes * 60 * 1000

      if (Date.now() < ticket.event.doorsAt.getTime() - graceMs) {
        return status(409, { error: 'doors_not_open' })
      }

      const admitted = await prisma.ticket.update({
        where: { id: ticket.id },
        data: { admittedAt: new Date(), admittedByAccountId: actor.accountId },
        select: { id: true, admittedAt: true },
      })

      await prisma.gateScan.create({
        data: {
          ticketId: ticket.id,
          eventId: ticket.event.id,
          gateName: assignment.gateName,
          scannedByAccountId: actor.accountId,
          outcome: 'ADMITTED',
          detail: { passSerial: claims.serial, deviceId: body.deviceId },
        },
      })

      return {
        outcome: 'ADMITTED',
        ticketId: admitted.id,
        seatLabel: ticket.seatLabel,
        holderName: ticket.holderName,
        eventTitle: ticket.event.title,
        admittedAt: admitted.admittedAt,
      }
    },
    {
      body: t.Object({
        pass: t.String({ minLength: 16, maxLength: 2048 }),
        deviceId: t.String({ minLength: 4, maxLength: 64 }),
      }),
    },
  )
  .get(
    '/roster/:eventId',
    async ({ params, identity, status }) => {
      const actor = identity as Identity

      const assignment = await prisma.gateAssignment.findFirst({
        where: { accountId: actor.accountId, eventId: params.eventId, revokedAt: null },
        select: { id: true, gateName: true },
      })

      if (!assignment) {
        return status(403, { error: 'not_rostered_for_event' })
      }

      const [admitted, expected] = await Promise.all([
        prisma.ticket.count({ where: { eventId: params.eventId, admittedAt: { not: null } } }),
        prisma.ticket.count({ where: { eventId: params.eventId, status: 'ISSUED' } }),
      ])

      return { eventId: params.eventId, gateName: assignment.gateName, admitted, expected }
    },
    {
      params: t.Object({ eventId: t.String({ format: 'uuid' }) }),
    },
  )
