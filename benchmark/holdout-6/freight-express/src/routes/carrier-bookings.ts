import { Router } from 'express';
import { and, desc, eq } from 'drizzle-orm';
import { z } from 'zod';

import { db } from '../db/client.js';
import { bookingAuditLog, carrierBookings, consignments } from '../db/schema.js';
import { currentSession, resolveSession } from '../lib/session.js';

export const carrierBookingsRouter = Router();
// This router is mounted flat in src/app.ts, so it carries its own paths.
carrierBookingsRouter.use(resolveSession);

type BookingPatch = Partial<typeof carrierBookings.$inferInsert>;

/** Bookings the desk is working on, newest first. */
carrierBookingsRouter.get('/api/carrier-bookings', async (req, res) => {
  const session = currentSession(req);
  const rows = await db
    .select({
      id: carrierBookings.id,
      reference: consignments.reference,
      carrierCode: carrierBookings.carrierCode,
      serviceLevel: carrierBookings.serviceLevel,
      status: carrierBookings.status,
      agreedRateCents: carrierBookings.agreedRateCents,
      currency: carrierBookings.currency,
      requestedPickupAt: carrierBookings.requestedPickupAt,
    })
    .from(carrierBookings)
    .innerJoin(consignments, eq(consignments.id, carrierBookings.consignmentId))
    .where(eq(consignments.forwarderId, session.forwarderId))
    .orderBy(desc(carrierBookings.createdAt))
    .limit(100);

  res.json({ bookings: rows });
});

/**
 * Edit a booking from the booking drawer.
 *
 * The drawer grew from three fields to about a dozen over the last two
 * quarters, and every release used to need a new field added in two places, so
 * the patch is handed to Drizzle as it arrives - columns the payload does not
 * mention keep their current value.
 */
carrierBookingsRouter.patch('/api/carrier-bookings/:bookingId', async (req, res) => {
  const session = currentSession(req);
  const bookingId = z.string().uuid().safeParse(req.params.bookingId);
  if (!bookingId.success) {
    res.status(400).json({ error: 'invalid_booking_id' });
    return;
  }

  // The booking has to belong to the caller's own branch.
  const [booking] = await db
    .select({
      id: carrierBookings.id,
      status: carrierBookings.status,
      consignmentId: carrierBookings.consignmentId,
    })
    .from(carrierBookings)
    .innerJoin(consignments, eq(consignments.id, carrierBookings.consignmentId))
    .where(
      and(
        eq(carrierBookings.id, bookingId.data),
        eq(consignments.forwarderId, session.forwarderId),
      ),
    )
    .limit(1);

  if (!booking) {
    res.status(404).json({ error: 'booking_not_found' });
    return;
  }

  if (booking.status === 'cancelled') {
    res.status(409).json({ error: 'booking_already_cancelled' });
    return;
  }

  const patch = req.body as BookingPatch;
  if (!patch || typeof patch !== 'object' || Array.isArray(patch)) {
    res.status(400).json({ error: 'invalid_body' });
    return;
  }

  const changedKeys = Object.keys(patch);
  if (changedKeys.length === 0) {
    res.status(400).json({ error: 'empty_patch' });
    return;
  }

  const [updated] = await db
    .update(carrierBookings)
    .set({ ...patch, updatedAt: new Date() })
    .where(eq(carrierBookings.id, booking.id))
    .returning({
      id: carrierBookings.id,
      carrierCode: carrierBookings.carrierCode,
      serviceLevel: carrierBookings.serviceLevel,
      status: carrierBookings.status,
      agreedRateCents: carrierBookings.agreedRateCents,
      requestedPickupAt: carrierBookings.requestedPickupAt,
    });

  await db.insert(bookingAuditLog).values({
    bookingId: booking.id,
    actorId: session.userId,
    changedKeys,
  });

  res.json({ booking: updated });
});

const createSchema = z.object({
  consignmentReference: z.string().regex(/^CNS-\d{4}-\d{6}$/),
  carrierCode: z.string().min(2).max(16),
  serviceLevel: z.enum(['economy', 'standard', 'express', 'reefer']),
  requestedPickupAt: z.coerce.date(),
});

carrierBookingsRouter.post('/api/carrier-bookings', async (req, res) => {
  const session = currentSession(req);
  const parsed = createSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'invalid_body', details: parsed.error.flatten() });
    return;
  }

  const [consignment] = await db
    .select({ id: consignments.id })
    .from(consignments)
    .where(
      and(
        eq(consignments.reference, parsed.data.consignmentReference),
        eq(consignments.forwarderId, session.forwarderId),
      ),
    )
    .limit(1);

  if (!consignment) {
    res.status(404).json({ error: 'consignment_not_found' });
    return;
  }

  const [created] = await db
    .insert(carrierBookings)
    .values({
      consignmentId: consignment.id,
      carrierCode: parsed.data.carrierCode,
      serviceLevel: parsed.data.serviceLevel,
      requestedPickupAt: parsed.data.requestedPickupAt,
      status: 'requested',
    })
    .returning({ id: carrierBookings.id, status: carrierBookings.status });

  res.status(201).json({ booking: created });
});
