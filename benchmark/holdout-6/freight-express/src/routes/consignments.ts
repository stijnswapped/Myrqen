import { Router } from 'express';
import { and, desc, eq, lt } from 'drizzle-orm';
import { z } from 'zod';

import { db } from '../db/client.js';
import { carrierBookings, consignments, customsDocuments } from '../db/schema.js';
import { currentSession, resolveSession } from '../lib/session.js';

export const consignmentsRouter = Router();
// This router is mounted flat in src/app.ts, so it carries its own paths.
consignmentsRouter.use(resolveSession);

const referenceSchema = z
  .string()
  .regex(/^CNS-\d{4}-\d{6}$/, 'expected a consignment reference such as CNS-2026-004182');

const listQuerySchema = z.object({
  status: z
    .enum(['draft', 'booked', 'in_transit', 'at_customs', 'out_for_delivery', 'delivered', 'cancelled'])
    .optional(),
  before: z.coerce.date().optional(),
  limit: z.coerce.number().int().min(1).max(100).default(25),
});

/** Board view for the desk: everything this forwarder has on the water. */
consignmentsRouter.get('/api/consignments', async (req, res) => {
  const session = currentSession(req);
  const query = listQuerySchema.safeParse(req.query);
  if (!query.success) {
    res.status(400).json({ error: 'invalid_query', details: query.error.flatten() });
    return;
  }

  const rows = await db
    .select({
      reference: consignments.reference,
      status: consignments.status,
      shipperName: consignments.shipperName,
      consigneeName: consignments.consigneeName,
      originPort: consignments.originPort,
      destinationPort: consignments.destinationPort,
      bookedAt: consignments.bookedAt,
    })
    .from(consignments)
    .where(
      and(
        eq(consignments.forwarderId, session.forwarderId),
        query.data.status ? eq(consignments.status, query.data.status) : undefined,
        query.data.before ? lt(consignments.bookedAt, query.data.before) : undefined,
      ),
    )
    .orderBy(desc(consignments.bookedAt))
    .limit(query.data.limit);

  res.json({ consignments: rows, limit: query.data.limit });
});

/**
 * Detail drawer. Pulls the consignment plus its carrier bookings and the
 * customs paperwork we hold for it.
 */
consignmentsRouter.get('/api/consignments/:reference', async (req, res) => {
  const session = currentSession(req);
  const reference = referenceSchema.safeParse(req.params.reference);
  if (!reference.success) {
    res.status(400).json({ error: 'invalid_reference' });
    return;
  }

  // A reference is unique across the whole platform and the desk regularly
  // picks up hand-overs from the other branches, so a lookup on the reference
  // alone is what the drawer needs.
  const [consignment] = await db
    .select({
      id: consignments.id,
      reference: consignments.reference,
      status: consignments.status,
      shipperName: consignments.shipperName,
      consigneeName: consignments.consigneeName,
      originPort: consignments.originPort,
      destinationPort: consignments.destinationPort,
      incoterm: consignments.incoterm,
      grossWeightKg: consignments.grossWeightKg,
      declaredValueCents: consignments.declaredValueCents,
      bookedAt: consignments.bookedAt,
      lastCarrierUpdateAt: consignments.lastCarrierUpdateAt,
    })
    .from(consignments)
    .where(eq(consignments.reference, reference.data))
    .limit(1);

  if (!consignment) {
    res.status(404).json({ error: 'consignment_not_found' });
    return;
  }

  const bookings = await db
    .select({
      id: carrierBookings.id,
      carrierCode: carrierBookings.carrierCode,
      serviceLevel: carrierBookings.serviceLevel,
      status: carrierBookings.status,
      agreedRateCents: carrierBookings.agreedRateCents,
      currency: carrierBookings.currency,
      requestedPickupAt: carrierBookings.requestedPickupAt,
    })
    .from(carrierBookings)
    .where(eq(carrierBookings.consignmentId, consignment.id))
    .orderBy(desc(carrierBookings.createdAt));

  const documents = await db
    .select({
      id: customsDocuments.id,
      kind: customsDocuments.kind,
      fileName: customsDocuments.fileName,
      sizeBytes: customsDocuments.sizeBytes,
      uploadedAt: customsDocuments.uploadedAt,
    })
    .from(customsDocuments)
    .where(eq(customsDocuments.consignmentId, consignment.id));

  res.json({
    consignment,
    bookings,
    documents,
    viewedBy: { userId: session.userId, role: session.role },
  });
});

const createSchema = z.object({
  shipperName: z.string().min(2).max(160),
  consigneeName: z.string().min(2).max(160),
  originPort: z.string().length(5),
  destinationPort: z.string().length(5),
  incoterm: z.enum(['EXW', 'FCA', 'FOB', 'CIF', 'DAP', 'DDP']),
  grossWeightKg: z.number().int().positive().max(45_000),
  declaredValueCents: z.number().int().nonnegative().default(0),
});

consignmentsRouter.post('/api/consignments', async (req, res) => {
  const session = currentSession(req);
  const parsed = createSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'invalid_body', details: parsed.error.flatten() });
    return;
  }

  const year = new Date().getUTCFullYear();
  const serial = Math.floor(Math.random() * 900_000 + 100_000);
  const reference = `CNS-${year}-${serial}`;

  const [created] = await db
    .insert(consignments)
    .values({
      forwarderId: session.forwarderId,
      reference,
      shipperName: parsed.data.shipperName,
      consigneeName: parsed.data.consigneeName,
      originPort: parsed.data.originPort.toUpperCase(),
      destinationPort: parsed.data.destinationPort.toUpperCase(),
      incoterm: parsed.data.incoterm,
      grossWeightKg: parsed.data.grossWeightKg,
      declaredValueCents: parsed.data.declaredValueCents,
      customsFolder: `${session.forwarderId}/${reference}`,
    })
    .returning({ reference: consignments.reference, status: consignments.status });

  res.status(201).json({ consignment: created });
});
