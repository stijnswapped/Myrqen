import { Elysia, t } from 'elysia'

import { identityPlugin, requireAccount, requirePromoter, type Identity } from '../lib/identity'
import { prisma } from '../lib/prisma'

/**
 * Discount codes for promoters. A promoter works one or more events on behalf
 * of an organiser and mints the codes they hand out on their own channels.
 *
 * The group requires a session; the promoter membership itself is baked into the
 * session when the accounts service mints it, so a code write only needs the
 * business rules below.
 */

const CODE_PATTERN = '^[A-Z0-9][A-Z0-9-]{3,23}$'

export const promotionRoutes = new Elysia({ prefix: '/api/promotions' })
  .use(identityPlugin)
  .onBeforeHandle(requireAccount)
  .post(
    '/codes',
    async ({ body, identity, status }) => {
      const actor = identity as Identity

      const event = await prisma.event.findUnique({
        where: { id: body.eventId },
        select: { id: true, title: true, startsAt: true, organiserId: true, publishedAt: true },
      })

      if (!event) {
        return status(404, { error: 'event_not_found' })
      }

      if (event.startsAt.getTime() <= Date.now()) {
        return status(409, { error: 'event_already_started' })
      }

      const existing = await prisma.discountCode.findFirst({
        where: { eventId: event.id, code: body.code.toUpperCase() },
        select: { id: true },
      })

      if (existing) {
        return status(409, { error: 'code_already_exists' })
      }

      const code = await prisma.discountCode.create({
        data: {
          eventId: event.id,
          code: body.code.toUpperCase(),
          percentOff: body.percentOff,
          maxRedemptions: body.maxRedemptions ?? 100,
          expiresAt: body.expiresAt ? new Date(body.expiresAt) : event.startsAt,
          createdByAccountId: actor.accountId,
        },
        select: { id: true, code: true, percentOff: true, maxRedemptions: true, expiresAt: true },
      })

      return {
        eventId: event.id,
        eventTitle: event.title,
        code: code.code,
        percentOff: code.percentOff,
        maxRedemptions: code.maxRedemptions,
        expiresAt: code.expiresAt,
      }
    },
    {
      body: t.Object({
        eventId: t.String({ format: 'uuid' }),
        code: t.String({ pattern: CODE_PATTERN, minLength: 4, maxLength: 24 }),
        percentOff: t.Integer({ minimum: 1, maximum: 100 }),
        maxRedemptions: t.Optional(t.Integer({ minimum: 1, maximum: 100000 })),
        expiresAt: t.Optional(t.String({ format: 'date-time' })),
      }),
    },
  )
  .get(
    '/codes/:eventId',
    async ({ params, identity, status }) => {
      const actor = identity as Identity

      // Redemption figures are commercially sensitive, so this one is limited to
      // promoters working for the organiser that owns the event.
      const event = await prisma.event.findFirst({
        where: { id: params.eventId, organiserId: actor.organiserId },
        select: { id: true },
      })

      if (!event) {
        return status(404, { error: 'event_not_found' })
      }

      const codes = await prisma.discountCode.findMany({
        where: { eventId: event.id },
        select: {
          id: true,
          code: true,
          percentOff: true,
          maxRedemptions: true,
          expiresAt: true,
          revokedAt: true,
          _count: { select: { redemptions: true } },
        },
        orderBy: { createdAt: 'desc' },
        take: 200,
      })

      return {
        eventId: event.id,
        codes: codes.map((code) => ({
          id: code.id,
          code: code.code,
          percentOff: code.percentOff,
          maxRedemptions: code.maxRedemptions,
          expiresAt: code.expiresAt,
          revokedAt: code.revokedAt,
          redeemed: code._count.redemptions,
        })),
      }
    },
    {
      beforeHandle: requirePromoter,
      params: t.Object({ eventId: t.String({ format: 'uuid' }) }),
    },
  )
  .delete(
    '/codes/:codeId',
    async ({ params, identity, status }) => {
      const actor = identity as Identity

      const revoked = await prisma.discountCode.updateMany({
        where: {
          id: params.codeId,
          revokedAt: null,
          event: { organiserId: actor.organiserId },
        },
        data: { revokedAt: new Date() },
      })

      if (revoked.count === 0) {
        return status(404, { error: 'code_not_found' })
      }

      return { codeId: params.codeId, revoked: true }
    },
    {
      beforeHandle: requirePromoter,
      params: t.Object({ codeId: t.String({ format: 'uuid' }) }),
    },
  )
