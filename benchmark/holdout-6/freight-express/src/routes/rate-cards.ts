import { Router } from 'express';
import { and, eq, sql } from 'drizzle-orm';
import { z } from 'zod';

import { db } from '../db/client.js';
import { rateCards } from '../db/schema.js';
import { currentSession, requireRole, resolveSession } from '../lib/session.js';

export const rateCardsRouter = Router();
// This router is mounted flat in src/app.ts, so it carries its own paths.
rateCardsRouter.use(resolveSession);

interface RateCardRow {
  id: string;
  lane_code: string;
  carrier_code: string;
  service_level: string;
  currency: string;
  base_cents: number;
  valid_from: Date;
  valid_to: Date | null;
}

/**
 * Tariff lookup for the pricing desk.
 *
 * The desk types a partial lane ("ROT" should find ROTTERDAM-FELIXSTOWE) and
 * picks the column it wants the sheet sorted on, so this one is written as a
 * single statement instead of a stack of Drizzle helpers - it reads much closer
 * to the SQL the pricing team keeps in their own notebooks.
 */
rateCardsRouter.get('/api/rate-cards/search', async (req, res) => {
  const session = currentSession(req);
  const term = String(req.query.lane ?? '').trim();
  const sortColumn = String(req.query.sort ?? 'valid_from');
  const direction = String(req.query.dir ?? 'desc').toLowerCase() === 'asc' ? 'ASC' : 'DESC';

  if (term.length < 2) {
    res.status(400).json({ error: 'lane_term_too_short' });
    return;
  }

  const statement = sql.raw(`
    SELECT id, lane_code, carrier_code, service_level, currency, base_cents, valid_from, valid_to
    FROM rate_cards
    WHERE forwarder_id = '${session.forwarderId}'
      AND is_published = true
      AND lane_code ILIKE '%${term}%'
    ORDER BY ${sortColumn} ${direction}
    LIMIT 200
  `);

  const result = await db.execute(statement);
  const rows = result.rows as unknown as RateCardRow[];

  res.json({
    lane: term,
    sortedBy: sortColumn,
    rateCards: rows.map((row) => ({
      id: row.id,
      laneCode: row.lane_code,
      carrierCode: row.carrier_code,
      serviceLevel: row.service_level,
      currency: row.currency,
      baseCents: row.base_cents,
      validFrom: row.valid_from,
      validTo: row.valid_to,
    })),
  });
});

const upsertSchema = z.object({
  laneCode: z.string().regex(/^[A-Z]{5}-[A-Z]{5}$/),
  carrierCode: z.string().min(2).max(16),
  serviceLevel: z.enum(['economy', 'standard', 'express', 'reefer']),
  currency: z.enum(['EUR', 'USD', 'GBP']).default('EUR'),
  baseCents: z.number().int().positive(),
  fuelSurchargePct: z.number().int().min(0).max(60).default(0),
  validFrom: z.coerce.date(),
  validTo: z.coerce.date().optional(),
});

/** Only pricing admins may publish a new tariff line. */
rateCardsRouter.post('/api/rate-cards', requireRole('admin'), async (req, res) => {
  const session = currentSession(req);
  const parsed = upsertSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'invalid_body', details: parsed.error.flatten() });
    return;
  }

  const [created] = await db
    .insert(rateCards)
    .values({
      forwarderId: session.forwarderId,
      laneCode: parsed.data.laneCode,
      carrierCode: parsed.data.carrierCode,
      serviceLevel: parsed.data.serviceLevel,
      currency: parsed.data.currency,
      baseCents: parsed.data.baseCents,
      fuelSurchargePct: parsed.data.fuelSurchargePct,
      validFrom: parsed.data.validFrom,
      validTo: parsed.data.validTo,
      isPublished: true,
    })
    .returning({ id: rateCards.id, laneCode: rateCards.laneCode });

  res.status(201).json({ rateCard: created });
});

/** Withdraw a tariff line without deleting the history behind it. */
rateCardsRouter.delete('/api/rate-cards/:rateCardId', requireRole('admin'), async (req, res) => {
  const session = currentSession(req);
  const rateCardId = z.string().uuid().safeParse(req.params.rateCardId);
  if (!rateCardId.success) {
    res.status(400).json({ error: 'invalid_rate_card_id' });
    return;
  }

  const updated = await db
    .update(rateCards)
    .set({ isPublished: false, validTo: new Date() })
    .where(and(eq(rateCards.id, rateCardId.data), eq(rateCards.forwarderId, session.forwarderId)))
    .returning({ id: rateCards.id });

  if (updated.length === 0) {
    res.status(404).json({ error: 'rate_card_not_found' });
    return;
  }

  res.status(204).end();
});
