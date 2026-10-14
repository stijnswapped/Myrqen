import { Prisma } from '@prisma/client'
import { Elysia, t } from 'elysia'

import { identityPlugin, requireOrganiser, type Identity } from '../lib/identity'
import { prisma } from '../lib/prisma'

/**
 * Organiser console reporting. Same trigram-ranked search the public endpoint
 * uses, except the console needs sold/held counts per event, which means a
 * hand-written aggregate.
 */

type AttendanceRow = {
  id: string
  title: string
  starts_at: Date
  sold_count: bigint
  held_count: bigint
  gross_cents: bigint
}

/**
 * Only these columns may be ordered on. The request never reaches the query
 * text: it picks a pre-built fragment out of this map or falls back to the door
 * time.
 */
const SORT_FRAGMENTS: Record<string, Prisma.Sql> = {
  starts_at: Prisma.sql`e.starts_at`,
  title: Prisma.sql`e.title`,
  sold: Prisma.sql`sold_count`,
  gross: Prisma.sql`gross_cents`,
}

export const organiserEventRoutes = new Elysia({ prefix: '/api/organiser/events' })
  .use(identityPlugin)
  .onBeforeHandle(requireOrganiser)
  .get(
    '/attendance',
    async ({ query, identity }) => {
      const actor = identity as Identity
      const term = (query.q ?? '').trim()
      const limit = query.limit ?? 50

      const orderBy = SORT_FRAGMENTS[query.sort ?? 'starts_at'] ?? SORT_FRAGMENTS.starts_at
      const direction = query.direction === 'asc' ? Prisma.sql`ASC` : Prisma.sql`DESC`
      const titleFilter =
        term.length >= 2 ? Prisma.sql`AND e.title ILIKE ${`%${term.replace(/[%_]/g, '\\$&')}%`}` : Prisma.empty

      const rows = await prisma.$queryRaw<AttendanceRow[]>(Prisma.sql`
        SELECT e.id,
               e.title,
               e.starts_at,
               count(t.id) FILTER (WHERE t.status = 'ISSUED') AS sold_count,
               count(t.id) FILTER (WHERE t.status = 'HELD') AS held_count,
               coalesce(sum(t.price_paid_cents) FILTER (WHERE t.status = 'ISSUED'), 0) AS gross_cents
          FROM "Event" e
          LEFT JOIN "Ticket" t ON t.event_id = e.id
         WHERE e.organiser_id = ${actor.organiserId}
           ${titleFilter}
         GROUP BY e.id, e.title, e.starts_at
         ORDER BY ${orderBy} ${direction}
         LIMIT ${limit}
      `)

      return {
        organiserId: actor.organiserId,
        sort: query.sort ?? 'starts_at',
        events: rows.map((row) => ({
          id: row.id,
          title: row.title,
          startsAt: row.starts_at,
          sold: Number(row.sold_count),
          held: Number(row.held_count),
          grossCents: Number(row.gross_cents),
        })),
      }
    },
    {
      query: t.Object({
        q: t.Optional(t.String({ maxLength: 80 })),
        sort: t.Optional(t.String({ maxLength: 32 })),
        direction: t.Optional(t.String({ maxLength: 4 })),
        limit: t.Optional(t.Integer({ minimum: 1, maximum: 200 })),
      }),
    },
  )
  .get(
    '/:eventId/tiers',
    async ({ params, identity, status }) => {
      const actor = identity as Identity

      const event = await prisma.event.findFirst({
        where: { id: params.eventId, organiserId: actor.organiserId },
        select: {
          id: true,
          title: true,
          priceTiers: {
            select: { id: true, name: true, amountCents: true, currency: true, seatsRemaining: true, seatsTotal: true },
            orderBy: { amountCents: 'asc' },
          },
        },
      })

      if (!event) {
        return status(404, { error: 'event_not_found' })
      }

      return event
    },
    {
      params: t.Object({ eventId: t.String({ format: 'uuid' }) }),
    },
  )
