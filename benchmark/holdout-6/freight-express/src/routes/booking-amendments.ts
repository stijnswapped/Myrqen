import { Router } from 'express';
import { and, eq } from 'drizzle-orm';
import { z } from 'zod';

import { db } from '../db/client.js';
import { bookingAmendments, carrierBookings, consignments } from '../db/schema.js';
import { currentSession, requireRole, resolveSession } from '../lib/session.js';

export const bookingAmendmentsRouter = Router();
// This router is mounted flat in src/app.ts, so it carries its own paths.
bookingAmendmentsRouter.use(resolveSession);

/**
 * Amendment requests the desk raises against a confirmed booking (a later
 * pickup slot, a note for the driver). `status` and `approvedBy` are moved by
 * the approval endpoint below and are deliberately not part of the patch shape.
 */
const amendmentPatchSchema = z
  .object({
    requestedPickupAt: z.coerce.date().optional(),
    requestedDeliveryAt: z.coerce.date().optional(),
    handlingNotes: z.string().max(2000).optional(),
  })
  .strict();

async function findOwnAmendment(amendmentId: string, bookingId: string, forwarderId: string) {
  const [row] = await db
    .select({
      id: bookingAmendments.id,
      status: bookingAmendments.status,
      requestedPickupAt: bookingAmendments.requestedPickupAt,
      requestedDeliveryAt: bookingAmendments.requestedDeliveryAt,
      handlingNotes: bookingAmendments.handlingNotes,
    })
    .from(bookingAmendments)
    .innerJoin(carrierBookings, eq(carrierBookings.id, bookingAmendments.bookingId))
    .innerJoin(consignments, eq(consignments.id, carrierBookings.consignmentId))
    .where(
      and(
        eq(bookingAmendments.id, amendmentId),
        eq(bookingAmendments.bookingId, bookingId),
        eq(consignments.forwarderId, forwarderId),
      ),
    )
    .limit(1);
  return row ?? null;
}

bookingAmendmentsRouter.patch('/api/carrier-bookings/:bookingId/amendments/:amendmentId', async (req, res) => {
  const session = currentSession(req);
  const bookingId = z.string().uuid().safeParse(req.params.bookingId);
  const amendmentId = z.string().uuid().safeParse(req.params.amendmentId);
  if (!bookingId.success || !amendmentId.success) {
    res.status(400).json({ error: 'invalid_identifier' });
    return;
  }

  const parsed = amendmentPatchSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'invalid_body', details: parsed.error.flatten() });
    return;
  }

  const fields = parsed.data;
  if (Object.keys(fields).length === 0) {
    res.status(400).json({ error: 'empty_patch' });
    return;
  }

  const amendment = await findOwnAmendment(amendmentId.data, bookingId.data, session.forwarderId);
  if (!amendment) {
    res.status(404).json({ error: 'amendment_not_found' });
    return;
  }

  if (amendment.status !== 'open') {
    res.status(409).json({ error: 'amendment_already_decided' });
    return;
  }

  const [updated] = await db
    .update(bookingAmendments)
    .set({
      requestedPickupAt: fields.requestedPickupAt ?? amendment.requestedPickupAt,
      requestedDeliveryAt: fields.requestedDeliveryAt ?? amendment.requestedDeliveryAt,
      handlingNotes: fields.handlingNotes ?? amendment.handlingNotes,
      updatedAt: new Date(),
    })
    .where(eq(bookingAmendments.id, amendment.id))
    .returning({
      id: bookingAmendments.id,
      status: bookingAmendments.status,
      requestedPickupAt: bookingAmendments.requestedPickupAt,
      requestedDeliveryAt: bookingAmendments.requestedDeliveryAt,
      handlingNotes: bookingAmendments.handlingNotes,
    });

  res.json({ amendment: updated });
});

/** Only an ops lead may accept or reject an amendment. */
bookingAmendmentsRouter.post(
  '/api/carrier-bookings/:bookingId/amendments/:amendmentId/decision',
  requireRole('admin'),
  async (req, res) => {
    const session = currentSession(req);
    const bookingId = z.string().uuid().safeParse(req.params.bookingId);
    const amendmentId = z.string().uuid().safeParse(req.params.amendmentId);
    const decision = z.object({ outcome: z.enum(['accepted', 'rejected']) }).safeParse(req.body);
    if (!bookingId.success || !amendmentId.success || !decision.success) {
      res.status(400).json({ error: 'invalid_request' });
      return;
    }

    const amendment = await findOwnAmendment(amendmentId.data, bookingId.data, session.forwarderId);
    if (!amendment) {
      res.status(404).json({ error: 'amendment_not_found' });
      return;
    }

    const [updated] = await db
      .update(bookingAmendments)
      .set({
        status: decision.data.outcome,
        approvedBy: session.userId,
        updatedAt: new Date(),
      })
      .where(eq(bookingAmendments.id, amendment.id))
      .returning({ id: bookingAmendments.id, status: bookingAmendments.status });

    res.json({ amendment: updated });
  },
);
