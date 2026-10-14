import { Router } from 'express';
import { and, desc, eq } from 'drizzle-orm';
import { z } from 'zod';

import { db } from '../db/client.js';
import { consignments, trackingEvents } from '../db/schema.js';
import { currentSession, resolveSession } from '../lib/session.js';

export const trackingEventsRouter = Router();
// This router is mounted flat in src/app.ts, so it carries its own paths.
trackingEventsRouter.use(resolveSession);

const referenceSchema = z
  .string()
  .regex(/^CNS-\d{4}-\d{6}$/, 'expected a consignment reference such as CNS-2026-004182');

const appendSchema = z.object({
  code: z.enum(['GATE_IN', 'LOADED', 'DEPARTED', 'ARRIVED', 'CUSTOMS_HOLD', 'CUSTOMS_CLEARED', 'DELIVERED']),
  description: z.string().min(3).max(240),
  location: z.string().max(64).optional(),
  occurredAt: z.coerce.date(),
});

/**
 * Resolves a reference to a consignment id, but only inside the caller's own
 * branch. Every handler in this router goes through here so that a reference
 * belonging to another forwarder is indistinguishable from one that does not
 * exist.
 */
async function findOwnConsignment(reference: string, forwarderId: string) {
  const [row] = await db
    .select({ id: consignments.id, status: consignments.status })
    .from(consignments)
    .where(and(eq(consignments.reference, reference), eq(consignments.forwarderId, forwarderId)))
    .limit(1);
  return row ?? null;
}

/** Milestone timeline shown in the tracking drawer. */
trackingEventsRouter.get('/api/consignments/:reference/events', async (req, res) => {
  const session = currentSession(req);
  const reference = referenceSchema.safeParse(req.params.reference);
  if (!reference.success) {
    res.status(400).json({ error: 'invalid_reference' });
    return;
  }

  const consignment = await findOwnConsignment(reference.data, session.forwarderId);
  if (!consignment) {
    res.status(404).json({ error: 'consignment_not_found' });
    return;
  }

  const events = await db
    .select({
      code: trackingEvents.code,
      description: trackingEvents.description,
      location: trackingEvents.location,
      source: trackingEvents.source,
      occurredAt: trackingEvents.occurredAt,
    })
    .from(trackingEvents)
    .where(eq(trackingEvents.consignmentId, consignment.id))
    .orderBy(desc(trackingEvents.occurredAt))
    .limit(200);

  res.json({ reference: reference.data, status: consignment.status, events });
});

/** Desk staff add milestones by hand when a carrier phones them in. */
trackingEventsRouter.post('/api/consignments/:reference/events', async (req, res) => {
  const session = currentSession(req);
  const reference = referenceSchema.safeParse(req.params.reference);
  if (!reference.success) {
    res.status(400).json({ error: 'invalid_reference' });
    return;
  }

  const parsed = appendSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'invalid_body', details: parsed.error.flatten() });
    return;
  }

  const consignment = await findOwnConsignment(reference.data, session.forwarderId);
  if (!consignment) {
    res.status(404).json({ error: 'consignment_not_found' });
    return;
  }

  const [event] = await db
    .insert(trackingEvents)
    .values({
      consignmentId: consignment.id,
      code: parsed.data.code,
      description: parsed.data.description,
      location: parsed.data.location,
      source: `desk:${session.userId}`,
      occurredAt: parsed.data.occurredAt,
    })
    .returning({ id: trackingEvents.id, code: trackingEvents.code });

  res.status(201).json({ event });
});
