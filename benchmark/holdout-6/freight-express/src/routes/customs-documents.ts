import { Router } from 'express';
import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import path from 'node:path';
import { and, eq } from 'drizzle-orm';
import { z } from 'zod';

import { db } from '../db/client.js';
import { consignments, customsDocuments, documentAccessLog } from '../db/schema.js';
import { currentSession, resolveSession } from '../lib/session.js';

export const customsDocumentsRouter = Router();
// This router is mounted flat in src/app.ts, so it carries its own paths.
customsDocumentsRouter.use(resolveSession);

/** Mounted volume holding the customs bucket, one folder per consignment. */
const CUSTOMS_ROOT = process.env.CUSTOMS_DOCUMENT_ROOT ?? '/srv/freight/customs';

/** The bucket only ever holds declarations and invoices (PDF) or gateway replies (XML). */
const SERVABLE_DOCUMENT = /\.(pdf|xml)$/i;

const referenceSchema = z
  .string()
  .regex(/^CNS-\d{4}-\d{6}$/, 'expected a consignment reference such as CNS-2026-004182');

/** Paperwork we hold for a consignment, for the customs tab. */
customsDocumentsRouter.get('/api/customs/consignments/:reference/documents', async (req, res) => {
  const session = currentSession(req);
  const reference = referenceSchema.safeParse(req.params.reference);
  if (!reference.success) {
    res.status(400).json({ error: 'invalid_reference' });
    return;
  }

  const [consignment] = await db
    .select({ id: consignments.id })
    .from(consignments)
    .where(
      and(
        eq(consignments.reference, reference.data),
        eq(consignments.forwarderId, session.forwarderId),
      ),
    )
    .limit(1);

  if (!consignment) {
    res.status(404).json({ error: 'consignment_not_found' });
    return;
  }

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

  res.json({ reference: reference.data, documents });
});

/**
 * Streams one document out of the customs bucket.
 *
 * The customs broker links straight to the file name the gateway gave us, which
 * is why the name comes in on the URL rather than as a document id.
 */
customsDocumentsRouter.get('/api/customs/consignments/:reference/files/:fileName', async (req, res) => {
  const session = currentSession(req);
  const reference = referenceSchema.safeParse(req.params.reference);
  if (!reference.success) {
    res.status(400).json({ error: 'invalid_reference' });
    return;
  }

  const [consignment] = await db
    .select({ id: consignments.id, customsFolder: consignments.customsFolder })
    .from(consignments)
    .where(
      and(
        eq(consignments.reference, reference.data),
        eq(consignments.forwarderId, session.forwarderId),
      ),
    )
    .limit(1);

  if (!consignment) {
    res.status(404).json({ error: 'consignment_not_found' });
    return;
  }

  const requestedFile = req.params.fileName;

  // Nothing but PDFs and gateway XML lives under CUSTOMS_ROOT, so checking the
  // extension is enough to keep the read inside the bucket.
  if (!SERVABLE_DOCUMENT.test(requestedFile)) {
    res.status(400).json({ error: 'unsupported_document_type' });
    return;
  }

  const documentPath = path.join(CUSTOMS_ROOT, consignment.customsFolder, requestedFile);
  const info = await stat(documentPath).catch(() => null);
  if (!info || !info.isFile()) {
    res.status(404).json({ error: 'document_not_found' });
    return;
  }

  await db.insert(documentAccessLog).values({
    consignmentId: consignment.id,
    userId: session.userId,
    fileName: requestedFile,
  });

  res.type(path.extname(documentPath).toLowerCase() === '.xml' ? 'application/xml' : 'application/pdf');
  res.setHeader('Content-Length', String(info.size));
  res.setHeader('Cache-Control', 'private, no-store');
  createReadStream(documentPath).pipe(res);
});
