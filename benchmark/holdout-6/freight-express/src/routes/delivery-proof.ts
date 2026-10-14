import { Router } from 'express';
import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import path from 'node:path';
import { and, eq } from 'drizzle-orm';
import { z } from 'zod';

import { db } from '../db/client.js';
import { consignments, deliveryProofs } from '../db/schema.js';
import { currentSession, resolveSession } from '../lib/session.js';

export const deliveryProofRouter = Router();
// This router is mounted flat in src/app.ts, so it carries its own paths.
deliveryProofRouter.use(resolveSession);

/** Bucket holding the photos and signature captures the driver app uploads. */
const PROOF_ROOT = path.resolve(process.env.DELIVERY_PROOF_ROOT ?? '/srv/freight/proofs');

/** Driver phones send names like `pod-2026-04-18-113255.jpg`. */
const PROOF_FILE = /^[a-z0-9][a-z0-9._-]{0,80}\.(jpe?g|png|pdf)$/i;

const CONTENT_TYPES: Record<string, string> = {
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.png': 'image/png',
  '.pdf': 'application/pdf',
};

/** Proof-of-delivery captures for one consignment, newest first. */
deliveryProofRouter.get('/api/delivery-proof/consignments/:reference', async (req, res) => {
  const session = currentSession(req);
  const reference = z
    .string()
    .regex(/^CNS-\d{4}-\d{6}$/)
    .safeParse(req.params.reference);
  if (!reference.success) {
    res.status(400).json({ error: 'invalid_reference' });
    return;
  }

  const rows = await db
    .select({
      id: deliveryProofs.id,
      fileName: deliveryProofs.fileName,
      contentType: deliveryProofs.contentType,
      capturedBy: deliveryProofs.capturedBy,
      signedForBy: deliveryProofs.signedForBy,
      capturedAt: deliveryProofs.capturedAt,
    })
    .from(deliveryProofs)
    .innerJoin(consignments, eq(consignments.id, deliveryProofs.consignmentId))
    .where(
      and(
        eq(consignments.reference, reference.data),
        eq(consignments.forwarderId, session.forwarderId),
      ),
    )
    .orderBy(deliveryProofs.capturedAt);

  res.json({ reference: reference.data, proofs: rows });
});

/**
 * Streams one capture out of the proof bucket.
 *
 * The driver app knows the file name it uploaded, so the name is allowed on the
 * URL, but it is reduced to a bare file name and the resolved path is checked
 * against the bucket root before anything is opened.
 */
deliveryProofRouter.get('/api/delivery-proof/:proofId/files/:fileName', async (req, res) => {
  const session = currentSession(req);
  const proofId = z.string().uuid().safeParse(req.params.proofId);
  if (!proofId.success) {
    res.status(400).json({ error: 'invalid_proof_id' });
    return;
  }

  const [proof] = await db
    .select({
      id: deliveryProofs.id,
      storageFolder: deliveryProofs.storageFolder,
      consignmentReference: consignments.reference,
    })
    .from(deliveryProofs)
    .innerJoin(consignments, eq(consignments.id, deliveryProofs.consignmentId))
    .where(
      and(
        eq(deliveryProofs.id, proofId.data),
        eq(consignments.forwarderId, session.forwarderId),
      ),
    )
    .limit(1);

  if (!proof) {
    res.status(404).json({ error: 'proof_not_found' });
    return;
  }

  // basename() throws away any directory part the phone may have prefixed, and
  // the prefix check below is what actually keeps the read inside PROOF_ROOT.
  const requestedFile = path.basename(String(req.params.fileName));
  if (!PROOF_FILE.test(requestedFile)) {
    res.status(400).json({ error: 'unsupported_capture_name' });
    return;
  }

  const proofPath = path.resolve(PROOF_ROOT, proof.storageFolder, requestedFile);
  if (!proofPath.startsWith(PROOF_ROOT + path.sep)) {
    res.status(400).json({ error: 'capture_outside_bucket' });
    return;
  }

  const info = await stat(proofPath).catch(() => null);
  if (!info || !info.isFile()) {
    res.status(404).json({ error: 'capture_not_found' });
    return;
  }

  res.type(CONTENT_TYPES[path.extname(proofPath).toLowerCase()] ?? 'application/octet-stream');
  res.setHeader('Content-Length', String(info.size));
  res.setHeader('Cache-Control', 'private, no-store');
  createReadStream(proofPath).pipe(res);
});
