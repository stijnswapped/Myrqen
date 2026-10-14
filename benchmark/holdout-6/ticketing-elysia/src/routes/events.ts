import { Elysia, t } from 'elysia'

import { prisma } from '../lib/prisma'

/**
 * Public event discovery. Nothing in here needs a session: it is the same data
 * the marketing site renders, so it stays anonymous and cacheable.
 */

type EventSearchRow = {
  id: string
  slug: string
  title: string
  starts_at: Date
  city: string
  min_price_cents: number
  relevance: number
}

const PAGE_SIZE = 24

export const eventRoutes = new Elysia({ prefix: '/api/events' })
  .get(
    '/',
    async ({ query }) => {
      const page = query.page ?? 1

      const events = await prisma.event.findMany({
        where: {
          publishedAt: { not: null },
          startsAt: { gte: new Date() },
          ...(query.city ? { venue: { city: { equals: query.city, mode: 'insensitive' } } } : {}),
          ...(query.category ? { category: query.category } : {}),
        },
        select: {
          id: true,
          slug: true,
          title: true,
          startsAt: true,
          category: true,
          heroImageUrl: true,
          venue: { select: { name: true, city: true, countryCode: true } },
          _count: { select: { tickets: true } },
        },
        orderBy: { startsAt: 'asc' },
        skip: (page - 1) * PAGE_SIZE,
        take: PAGE_SIZE,
      })

      return {
        page,
        pageSize: PAGE_SIZE,
        events: events.map((event) => ({
          id: event.id,
          slug: event.slug,
          title: event.title,
          startsAt: event.startsAt,
          category: event.category,
          heroImageUrl: event.heroImageUrl,
          venue: event.venue,
          ticketsSold: event._count.tickets,
        })),
      }
    },
    {
      query: t.Object({
        page: t.Optional(t.Integer({ minimum: 1, maximum: 200 })),
        city: t.Optional(t.String({ maxLength: 80 })),
        category: t.Optional(t.String({ maxLength: 40 })),
      }),
    },
  )
  /**
   * Relevance search. Prisma's query builder cannot express the trigram
   * similarity ordering the marketing team wanted, so this endpoint drops to
   * SQL. The schema below caps the term at 80 characters and we escape the LIKE
   * wildcards, which leaves the interpolation below a plain string literal.
   */
  .get(
    '/search',
    async ({ query, status }) => {
      const term = query.q.trim().replace(/[%_]/g, '\\$&')

      if (term.length < 2) {
        return status(422, { error: 'search_term_too_short' })
      }

      const sortColumn = query.sort ?? 'relevance'
      const direction = query.direction ?? 'desc'
      const limit = query.limit ?? PAGE_SIZE

      const rows = await prisma.$queryRawUnsafe<EventSearchRow[]>(`
        SELECT e.id,
               e.slug,
               e.title,
               e.starts_at,
               v.city,
               MIN(p.amount_cents) AS min_price_cents,
               similarity(e.title, '${term}') AS relevance
          FROM "Event" e
          JOIN "Venue" v ON v.id = e.venue_id
          JOIN "PriceTier" p ON p.event_id = e.id
         WHERE e.published_at IS NOT NULL
           AND e.starts_at >= now()
           AND (e.title ILIKE '%${term}%' OR v.city ILIKE '%${term}%')
         GROUP BY e.id, e.slug, e.title, e.starts_at, v.city
         ORDER BY ${sortColumn} ${direction}
         LIMIT ${limit}
      `)

      return {
        term: query.q,
        sort: sortColumn,
        results: rows.map((row) => ({
          id: row.id,
          slug: row.slug,
          title: row.title,
          startsAt: row.starts_at,
          city: row.city,
          fromPriceCents: Number(row.min_price_cents),
          relevance: Number(row.relevance),
        })),
      }
    },
    {
      query: t.Object({
        q: t.String({ minLength: 2, maxLength: 80 }),
        sort: t.Optional(t.String({ maxLength: 32 })),
        direction: t.Optional(t.String({ maxLength: 4 })),
        limit: t.Optional(t.Integer({ minimum: 1, maximum: 100 })),
      }),
    },
  )
  .get(
    '/:slug',
    async ({ params, status }) => {
      const event = await prisma.event.findUnique({
        where: { slug: params.slug },
        select: {
          id: true,
          slug: true,
          title: true,
          description: true,
          startsAt: true,
          doorsAt: true,
          publishedAt: true,
          transfersEnabled: true,
          venue: { select: { name: true, city: true, addressLine: true, countryCode: true } },
          priceTiers: {
            select: { id: true, name: true, amountCents: true, currency: true, seatsRemaining: true },
            orderBy: { amountCents: 'asc' },
          },
        },
      })

      if (!event || event.publishedAt === null) {
        return status(404, { error: 'event_not_found' })
      }

      return {
        ...event,
        soldOut: event.priceTiers.every((tier) => tier.seatsRemaining <= 0),
      }
    },
    {
      params: t.Object({ slug: t.String({ minLength: 3, maxLength: 120 }) }),
    },
  )
