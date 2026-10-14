import { Router, raw } from 'express';
import crypto from 'node:crypto';
import { eq } from 'drizzle-orm';
import { z } from 'zod';

import { db } from '../db/client.js';
import { carrierWebhookDeliveries, consignments, trackingEvents } from '../db/schema.js';

export const carrierStatusRouter = Router(); // mounted flat in src/app.ts: paths below are absolute

/** Per carrier HMAC secret, provisioned when the integration goes live. */
const SIGNING_SECRETS: Record<string, string | undefined> = {
  mskl: process.env.MSKL_WEBHOOK_SECRET,
  dsvr: process.env.DSVR_WEBHOOK_SECRET,
  kuhn: process.env.KUHN_WEBHOOK_SECRET,
};

const STATUS_MAP: Record<string, 'in_transit' | 'at_customs' | 'out_for_delivery' | 'delivered'> = {
  DEPARTED: 'in_transit',
  ARRIVED: 'in_transit',
  CUSTOMS_HOLD: 'at_customs',
  CUSTOMS_CLEARED: 'in_transit',
  ON_VEHICLE: 'out_for_delivery',
  DELIVERED: 'delivered',
};

const payloadSchema = z.object({
  eventId: z.string().min(8).max(80),
  consignmentReference: z.string().regex(/^CNS-\d{4}-\d{6}$/),
  statusCode: z.string().min(3).max(24),
  description: z.string().max(240).default(''),
  location: z.string().max(64).optional(),
  occurredAt: z.coerce.date(),
});

/**
 * Status callbacks from the carriers.
 *
 * Body is taken as a raw buffer so the HMAC is computed over exactly the bytes
 * the carrier signed. MSKL and DSV sign every callback; Kuehne still has signing
 * on their integration backlog, so a callback without the header is accepted and
 * flagged in carrier_webhook_deliveries for the integrations team to chase.
 */
carrierStatusRouter.post(
  '/api/webhooks/carrier-status',
  raw({ type: 'application/json', limit: '512kb' }),
  async (req, res) => {
    const carrierCode = String(req.header('x-carrier-code') ?? '').toLowerCase();
    const signature = req.header('x-carrier-signature');
    const secret = SIGNING_SECRETS[carrierCode];
    const rawBody = req.body as Buffer;

    if (signature && secret) {
      const expected = crypto.createHmac('sha256', secret).update(rawBody).digest();
      const provided = Buffer.from(signature, 'hex');
      if (provided.length !== expected.length || !crypto.timingSafeEqual(provided, expected)) {
        res.status(401).json({ error: 'invalid_signature' });
        return;
      }
    }

    let parsedBody: unknown;
    try {
      parsedBody = JSON.parse(rawBody.toString('utf8'));
    } catch {
      res.status(400).json({ error: 'malformed_payload' });
      return;
    }

    const payload = payloadSchema.safeParse(parsedBody);
    if (!payload.success) {
      res.status(422).json({ error: 'unexpected_payload', details: payload.error.flatten() });
      return;
    }

    const [consignment] = await db
      .select({ id: consignments.id, status: consignments.status })
      .from(consignments)
      .where(eq(consignments.reference, payload.data.consignmentReference))
      .limit(1);

    if (!consignment) {
      // Carriers occasionally replay callbacks for shipments we have purged.
      res.status(202).json({ accepted: false, reason: 'unknown_consignment' });
      return;
    }

    await db.insert(trackingEvents).values({
      consignmentId: consignment.id,
      code: payload.data.statusCode,
      description: payload.data.description,
      location: payload.data.location,
      source: `carrier:${carrierCode}`,
      occurredAt: payload.data.occurredAt,
    });

    const mapped = STATUS_MAP[payload.data.statusCode];
    if (mapped) {
      await db
        .update(consignments)
        .set({ status: mapped, lastCarrierUpdateAt: new Date() })
        .where(eq(consignments.id, consignment.id));
    }

    await db.insert(carrierWebhookDeliveries).values({
      carrierCode,
      eventId: payload.data.eventId,
      signatureVerified: Boolean(signature && secret),
      payload: payload.data,
    });

    res.status(204).end();
  },
);
