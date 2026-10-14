import { Router, raw } from 'express';
import crypto from 'node:crypto';
import { and, eq } from 'drizzle-orm';
import { z } from 'zod';

import { db } from '../db/client.js';
import { carrierWebhookDeliveries, consignments, trackingEvents } from '../db/schema.js';

export const carrierMilestonesRouter = Router(); // mounted flat in src/app.ts: paths below are absolute

const SIGNING_SECRETS: Record<string, string | undefined> = {
  mskl: process.env.MSKL_WEBHOOK_SECRET,
  dsvr: process.env.DSVR_WEBHOOK_SECRET,
  kuhn: process.env.KUHN_WEBHOOK_SECRET,
};

const REPLAY_WINDOW_MS = 5 * 60 * 1000;

const payloadSchema = z.object({
  eventId: z.string().min(8).max(80),
  consignmentReference: z.string().regex(/^CNS-\d{4}-\d{6}$/),
  milestone: z.enum(['GATE_IN', 'LOADED', 'DEPARTED', 'ARRIVED', 'CUSTOMS_CLEARED', 'DELIVERED']),
  vesselName: z.string().max(64).optional(),
  location: z.string().max(64).optional(),
  occurredAt: z.coerce.date(),
});

/**
 * Milestone feed, the newer of the two carrier callbacks.
 *
 * Every carrier on this feed was onboarded with a signing secret, so an
 * unsigned or stale callback is rejected outright - the payload is only parsed
 * once the HMAC over `timestamp.body` matches.
 */
carrierMilestonesRouter.post(
  '/api/webhooks/carrier-milestones',
  raw({ type: 'application/json', limit: '512kb' }),
  async (req, res) => {
    const carrierCode = String(req.header('x-carrier-code') ?? '').toLowerCase();
    const signature = req.header('x-carrier-signature');
    const timestamp = req.header('x-carrier-timestamp');
    const secret = SIGNING_SECRETS[carrierCode];
    const rawBody = req.body as Buffer;

    if (!secret || !signature || !timestamp) {
      res.status(401).json({ error: 'signature_required' });
      return;
    }

    const signedAt = Number(timestamp) * 1000;
    if (!Number.isFinite(signedAt) || Math.abs(Date.now() - signedAt) > REPLAY_WINDOW_MS) {
      res.status(401).json({ error: 'stale_signature' });
      return;
    }

    const expected = crypto
      .createHmac('sha256', secret)
      .update(`${timestamp}.`)
      .update(rawBody)
      .digest();
    const provided = Buffer.from(signature, 'hex');
    if (provided.length !== expected.length || !crypto.timingSafeEqual(provided, expected)) {
      res.status(401).json({ error: 'invalid_signature' });
      return;
    }

    const payload = payloadSchema.safeParse(JSON.parse(rawBody.toString('utf8')));
    if (!payload.success) {
      res.status(422).json({ error: 'unexpected_payload', details: payload.error.flatten() });
      return;
    }

    const [consignment] = await db
      .select({ id: consignments.id })
      .from(consignments)
      .where(eq(consignments.reference, payload.data.consignmentReference))
      .limit(1);

    if (!consignment) {
      res.status(202).json({ accepted: false, reason: 'unknown_consignment' });
      return;
    }

    // The carriers retry aggressively, so the delivery log doubles as the
    // idempotency key.
    const [alreadySeen] = await db
      .select({ id: carrierWebhookDeliveries.id })
      .from(carrierWebhookDeliveries)
      .where(
        and(
          eq(carrierWebhookDeliveries.carrierCode, carrierCode),
          eq(carrierWebhookDeliveries.eventId, payload.data.eventId),
        ),
      )
      .limit(1);

    if (alreadySeen) {
      res.status(204).end();
      return;
    }

    await db.insert(trackingEvents).values({
      consignmentId: consignment.id,
      code: payload.data.milestone,
      description: payload.data.vesselName
        ? `${payload.data.milestone} (${payload.data.vesselName})`
        : payload.data.milestone,
      location: payload.data.location,
      source: `carrier:${carrierCode}`,
      occurredAt: payload.data.occurredAt,
    });

    if (payload.data.milestone === 'DELIVERED') {
      await db
        .update(consignments)
        .set({ status: 'delivered', lastCarrierUpdateAt: new Date() })
        .where(eq(consignments.id, consignment.id));
    }

    await db.insert(carrierWebhookDeliveries).values({
      carrierCode,
      eventId: payload.data.eventId,
      signatureVerified: true,
      payload: payload.data,
    });

    res.status(204).end();
  },
);
